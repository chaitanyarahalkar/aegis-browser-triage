use crate::{
    MAX_DIAGNOSTICS, MAX_MATCHING_RULES, MAX_REPORTED_MATCHES, MAX_RULE_SOURCE_BYTES, MAX_RULES,
    MAX_SAMPLE_BYTES, YARA_SCHEMA_VERSION, YaraCompileFailure, YaraCompileSummary, YaraDiagnostic,
    YaraMetadata, YaraOccurrence, YaraPackSummary, YaraPatternMatch, YaraReport, YaraRuleMatch,
    YaraScanOptions, YaraStats,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use yara_x::{Compiler, MetaValue, PatternKind, Rules, Scanner, SourceCode};

#[derive(Debug, Error)]
pub enum YaraError {
    #[error("rule source is empty")]
    EmptySource,
    #[error("rule source exceeds the 1 MiB hard limit")]
    SourceTooLarge,
    #[error("compiled pack exceeds the 10000 rule hard limit")]
    TooManyRules,
    #[error("sample is empty")]
    EmptySample,
    #[error("sample exceeds the 128 MiB hard limit")]
    SampleTooLarge,
    #[error("YARA scan failed: {0}")]
    Scan(String),
}

pub struct CompiledYaraRules {
    rules: Rules,
    summary: YaraCompileSummary,
}

impl CompiledYaraRules {
    pub fn compile(
        pack_name: &str,
        source_name: &str,
        namespace: &str,
        source: &str,
    ) -> Result<Self, YaraCompileFailure> {
        if source.trim().is_empty() {
            return Err(simple_failure(YaraError::EmptySource));
        }
        if source.len() > MAX_RULE_SOURCE_BYTES {
            return Err(simple_failure(YaraError::SourceTooLarge));
        }

        let mut compiler = Compiler::new();
        compiler
            .enable_includes(false)
            .relaxed_re_syntax(true)
            .error_on_slow_pattern(true)
            .error_on_slow_loop(true)
            .max_warnings(MAX_DIAGNOSTICS)
            .new_namespace(&sanitize_namespace(namespace));
        for module in [
            "console", "crx", "cuckoo", "dex", "lnk", "magic", "olecf", "vba", "vt", "zip",
        ] {
            compiler.ban_module(
                module,
                "module disabled in browser build",
                format!("the `{module}` module is not enabled in NOPE's browser-safe YARA build"),
            );
        }

        let source_name = sanitize_name(source_name, "custom.yar");
        let added = compiler.add_source(SourceCode::from(source).with_origin(source_name.clone()));
        if added.is_err() {
            return Err(YaraCompileFailure {
                message: "YARA rule compilation failed".into(),
                errors: compiler
                    .errors()
                    .iter()
                    .take(MAX_DIAGNOSTICS)
                    .map(|error| diagnostic("error", error))
                    .collect(),
                warnings: compiler
                    .warnings()
                    .iter()
                    .take(MAX_DIAGNOSTICS)
                    .map(|warning| diagnostic("warning", warning))
                    .collect(),
            });
        }

        let warnings = compiler
            .warnings()
            .iter()
            .take(MAX_DIAGNOSTICS)
            .map(|warning| diagnostic("warning", warning))
            .collect();
        let rules = compiler.build();
        let rule_count = rules.iter().len();
        if rule_count > MAX_RULES {
            return Err(simple_failure(YaraError::TooManyRules));
        }
        let pack_name = sanitize_name(pack_name, "Custom pack");
        let namespace = sanitize_namespace(namespace);
        let summary = YaraCompileSummary {
            schema_version: YARA_SCHEMA_VERSION,
            engine_version: env!("CARGO_PKG_VERSION").into(),
            pack_name,
            source_name,
            namespace,
            source_sha256: hex::encode(Sha256::digest(source.as_bytes())),
            rule_count,
            warnings,
        };
        Ok(Self { rules, summary })
    }

    pub fn summary(&self) -> &YaraCompileSummary {
        &self.summary
    }

    pub fn scan(
        &self,
        sample_name: &str,
        bytes: &[u8],
        options: &YaraScanOptions,
    ) -> Result<YaraReport, YaraError> {
        if bytes.is_empty() {
            return Err(YaraError::EmptySample);
        }
        if bytes.len() > MAX_SAMPLE_BYTES {
            return Err(YaraError::SampleTooLarge);
        }
        let options = options.clone().bounded();
        let mut scanner = Scanner::new(&self.rules);
        scanner
            .use_mmap(false)
            .max_scan_size(MAX_SAMPLE_BYTES)
            .max_matches_per_pattern(options.max_matches_per_pattern);
        let result = scanner
            .scan(bytes)
            .map_err(|error| YaraError::Scan(error.to_string()))?;

        let mut matches = Vec::new();
        let mut reported_occurrences = 0usize;
        let mut matched_patterns = 0usize;
        let mut truncated = false;
        for rule in result.matching_rules() {
            if matches.len() >= MAX_MATCHING_RULES {
                truncated = true;
                break;
            }
            let metadata: Vec<_> = rule
                .metadata()
                .map(|(identifier, value)| YaraMetadata {
                    identifier: identifier.to_owned(),
                    value: metadata_value(value),
                })
                .collect();
            let severity = severity_from_metadata(&metadata);
            let mut patterns = Vec::new();
            for pattern in rule.patterns().include_private(true) {
                let mut occurrences = Vec::new();
                for occurrence in pattern.matches() {
                    if reported_occurrences
                        >= options.max_reported_matches.min(MAX_REPORTED_MATCHES)
                    {
                        truncated = true;
                        break;
                    }
                    let range = occurrence.range();
                    occurrences.push(YaraOccurrence {
                        offset: range.start as u64,
                        length: range.len() as u64,
                        xor_key: occurrence.xor_key(),
                    });
                    reported_occurrences += 1;
                }
                if !occurrences.is_empty() {
                    matched_patterns += 1;
                    patterns.push(YaraPatternMatch {
                        identifier: pattern.identifier().to_owned(),
                        kind: match pattern.kind() {
                            PatternKind::Text => "text",
                            PatternKind::Hex => "hex",
                            PatternKind::Regexp => "regexp",
                        }
                        .into(),
                        occurrences,
                    });
                }
                if reported_occurrences >= options.max_reported_matches.min(MAX_REPORTED_MATCHES) {
                    break;
                }
            }
            matches.push(YaraRuleMatch {
                identifier: rule.identifier().to_owned(),
                namespace: rule.namespace().to_owned(),
                tags: rule.tags().map(|tag| tag.identifier().to_owned()).collect(),
                metadata,
                severity,
                patterns,
            });
        }
        matches.sort_by(|a, b| {
            a.namespace
                .cmp(&b.namespace)
                .then(a.identifier.cmp(&b.identifier))
        });
        let matching_rules = matches.len();
        Ok(YaraReport {
            schema_version: YARA_SCHEMA_VERSION,
            engine_version: env!("CARGO_PKG_VERSION").into(),
            sample_name: sanitize_name(sample_name, "sample.bin"),
            sample_sha256: hex::encode(Sha256::digest(bytes)),
            pack: YaraPackSummary {
                name: self.summary.pack_name.clone(),
                namespace: self.summary.namespace.clone(),
                source_name: self.summary.source_name.clone(),
                source_sha256: self.summary.source_sha256.clone(),
                rule_count: self.summary.rule_count,
            },
            elapsed_ms: 0.0,
            matches,
            stats: YaraStats {
                rules_scanned: self.summary.rule_count,
                matching_rules,
                matched_patterns,
                reported_occurrences,
            },
            truncated,
        })
    }
}

fn diagnostic<T: Serialize + ToString>(level: &str, value: &T) -> YaraDiagnostic {
    YaraDiagnostic {
        level: level.into(),
        message: value.to_string(),
        details: serde_json::to_value(value).unwrap_or_else(|_| json!({})),
    }
}

fn simple_failure(error: YaraError) -> YaraCompileFailure {
    let message = error.to_string();
    YaraCompileFailure {
        message: message.clone(),
        errors: vec![YaraDiagnostic {
            level: "error".into(),
            message,
            details: json!({}),
        }],
        warnings: Vec::new(),
    }
}

fn metadata_value(value: MetaValue<'_>) -> Value {
    match value {
        MetaValue::Integer(value) => json!(value),
        MetaValue::Float(value) => json!(value),
        MetaValue::Bool(value) => json!(value),
        MetaValue::String(value) => json!(value),
        MetaValue::Bytes(value) => json!(String::from_utf8_lossy(value).into_owned()),
    }
}

fn severity_from_metadata(metadata: &[YaraMetadata]) -> String {
    let value = metadata
        .iter()
        .find(|item| item.identifier.eq_ignore_ascii_case("severity"))
        .and_then(|item| item.value.as_str())
        .unwrap_or("info")
        .to_ascii_lowercase();
    match value.as_str() {
        "critical" | "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    }
    .into()
}

fn sanitize_name(value: &str, fallback: &str) -> String {
    let value: String = value
        .chars()
        .filter(|character| !character.is_control())
        .take(255)
        .collect();
    if value.trim().is_empty() {
        fallback.into()
    } else {
        value
    }
}

fn sanitize_namespace(value: &str) -> String {
    let mut result: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if result.is_empty() || result.as_bytes()[0].is_ascii_digit() {
        result.insert_str(0, "custom_");
    }
    result
}
