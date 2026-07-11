mod code;
mod formats;
mod model;

pub use model::*;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("sample is empty")]
    Empty,
    #[error("sample exceeds the {max_bytes} byte hard limit")]
    TooLarge { max_bytes: usize },
    #[error("failed to parse {format}: {message}")]
    Parse {
        format: &'static str,
        message: String,
    },
}

pub fn analyze(
    name: impl Into<String>,
    bytes: &[u8],
    options: &AnalysisOptions,
) -> Result<AnalysisReport, AnalysisError> {
    if bytes.is_empty() {
        return Err(AnalysisError::Empty);
    }
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(AnalysisError::TooLarge {
            max_bytes: MAX_INPUT_BYTES,
        });
    }

    let options = options.clone().bounded();
    let mut parsed = formats::parse(bytes)?;
    let (strings, strings_truncated) = extract_strings(bytes, &options);
    let indicators = extract_indicators(&strings);
    let code = code::analyze(
        bytes,
        &parsed.format,
        parsed.architecture.as_deref(),
        &parsed.sections,
        &parsed.imports,
        &parsed.exports,
        &strings,
    );

    add_common_findings(
        &mut parsed.findings,
        &parsed.sections,
        &indicators,
        bytes.len(),
    );
    parsed
        .findings
        .sort_by_key(|finding| match finding.severity {
            Severity::High => 0,
            Severity::Medium => 1,
            Severity::Low => 2,
            Severity::Info => 3,
        });

    Ok(AnalysisReport {
        schema_version: SCHEMA_VERSION,
        engine_version: env!("CARGO_PKG_VERSION").to_owned(),
        sample: SampleSummary {
            name: sanitize_name(&name.into()),
            size: bytes.len() as u64,
            detected_format: parsed.binary_format,
            architecture: parsed.architecture,
            sha256: digest_hex::<Sha256>(bytes),
            sha1: digest_hex::<Sha1>(bytes),
            md5: digest_hex::<Md5>(bytes),
        },
        format: parsed.format,
        sections: parsed.sections,
        imports: parsed.imports,
        exports: parsed.exports,
        strings,
        indicators,
        code,
        findings: parsed.findings,
        warnings: parsed.warnings,
        stats: AnalysisStats {
            // Platform adapters fill this using their monotonic clock. Keeping
            // the core clock-free makes reports deterministic and avoids
            // unsupported `std::time` calls on wasm32-unknown-unknown.
            elapsed_ms: 0.0,
            bytes_scanned: bytes.len() as u64,
            strings_truncated,
            collections_truncated: parsed.collections_truncated,
        },
    })
}

fn digest_hex<D: Digest + Default>(bytes: &[u8]) -> String {
    let mut digest = D::default();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

fn sanitize_name(name: &str) -> String {
    let leaf = name.rsplit(['/', '\\']).next().unwrap_or("sample.bin");
    let clean: String = leaf
        .chars()
        .filter(|ch| !ch.is_control())
        .take(255)
        .collect();
    if clean.is_empty() {
        "sample.bin".into()
    } else {
        clean
    }
}

fn extract_strings(bytes: &[u8], options: &AnalysisOptions) -> (Vec<ExtractedString>, bool) {
    let mut result = Vec::new();
    let mut total_bytes = 0usize;
    let mut truncated = false;

    let mut start = 0usize;
    while start < bytes.len() {
        if is_printable(bytes[start]) {
            let mut end = start + 1;
            while end < bytes.len() && is_printable(bytes[end]) {
                end += 1;
            }
            if end - start >= options.min_string_length {
                let length = (end - start).min(MAX_STRING_LENGTH);
                let value = String::from_utf8_lossy(&bytes[start..start + length]).into_owned();
                if !push_string(
                    &mut result,
                    &mut total_bytes,
                    options,
                    start,
                    "ascii",
                    value,
                ) {
                    truncated = true;
                    break;
                }
                truncated |= length < end - start;
            }
            start = end;
        } else {
            start += 1;
        }
    }

    if result.len() < options.max_strings && total_bytes < MAX_STRING_BYTES {
        let mut index = 0usize;
        while index + 1 < bytes.len() {
            if is_printable(bytes[index]) && bytes[index + 1] == 0 {
                let start = index;
                let mut chars = Vec::new();
                while index + 1 < bytes.len()
                    && is_printable(bytes[index])
                    && bytes[index + 1] == 0
                    && chars.len() < MAX_STRING_LENGTH
                {
                    chars.push(bytes[index]);
                    index += 2;
                }
                if chars.len() >= options.min_string_length {
                    let value = String::from_utf8_lossy(&chars).into_owned();
                    if !push_string(
                        &mut result,
                        &mut total_bytes,
                        options,
                        start,
                        "utf-16le",
                        value,
                    ) {
                        truncated = true;
                        break;
                    }
                }
            } else {
                index += 1;
            }
        }
    }

    (result, truncated)
}

fn push_string(
    strings: &mut Vec<ExtractedString>,
    total_bytes: &mut usize,
    options: &AnalysisOptions,
    offset: usize,
    encoding: &str,
    value: String,
) -> bool {
    if strings.len() >= options.max_strings || *total_bytes + value.len() > MAX_STRING_BYTES {
        return false;
    }
    *total_bytes += value.len();
    strings.push(ExtractedString {
        offset: offset as u64,
        encoding: encoding.to_owned(),
        value,
    });
    true
}

fn is_printable(byte: u8) -> bool {
    matches!(byte, b' '..=b'~' | b'\t')
}

fn extract_indicators(strings: &[ExtractedString]) -> Vec<Indicator> {
    let mut indicators = Vec::new();
    for item in strings {
        for token in item.value.split(|ch: char| {
            ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']')
        }) {
            let trimmed = token.trim_matches(|ch: char| matches!(ch, ',' | ';' | ':' | '.'));
            let lower = trimmed.to_ascii_lowercase();
            let kind = if lower.starts_with("http://") || lower.starts_with("https://") {
                Some("url")
            } else if lower.starts_with("powershell")
                || lower.contains("cmd.exe")
                || lower.contains("/bin/sh")
            {
                Some("command")
            } else if lower.starts_with("hkey_")
                || lower.starts_with("hkcu\\")
                || lower.starts_with("hklm\\")
            {
                Some("registry")
            } else if looks_like_ipv4(trimmed) {
                Some("ipv4")
            } else if looks_like_domain(trimmed) {
                Some("domain")
            } else {
                None
            };
            if let Some(kind) = kind
                && !indicators
                    .iter()
                    .any(|existing: &Indicator| existing.kind == kind && existing.value == trimmed)
            {
                indicators.push(Indicator {
                    kind: kind.to_owned(),
                    value: trimmed.chars().take(512).collect(),
                    offset: item.offset,
                });
                if indicators.len() >= MAX_COLLECTION_ITEMS {
                    return indicators;
                }
            }
        }
    }
    indicators
}

fn looks_like_ipv4(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
}

fn looks_like_domain(value: &str) -> bool {
    let value = value.trim_end_matches('.');
    value.len() >= 4
        && value.len() <= 253
        && value.contains('.')
        && !value.contains('/')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn add_common_findings(
    findings: &mut Vec<Finding>,
    sections: &[SectionRecord],
    indicators: &[Indicator],
    sample_size: usize,
) {
    for section in sections
        .iter()
        .filter(|section| section.entropy >= 7.2 && section.size >= 1_024)
    {
        findings.push(Finding {
            id: "high-entropy-section".into(),
            title: "High-entropy section".into(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            rationale: "Compressed, encrypted, or packed content commonly has high byte entropy."
                .into(),
            evidence: vec![Evidence {
                offset: Some(section.offset),
                length: Some(section.size),
                value: format!("{}: {:.2} bits/byte", section.name, section.entropy),
            }],
        });
    }

    for section in sections
        .iter()
        .filter(|section| section.permissions.contains('w') && section.permissions.contains('x'))
    {
        findings.push(Finding {
            id: "writable-executable-section".into(),
            title: "Writable and executable section".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            rationale: "A region that is both writable and executable can enable runtime code modification.".into(),
            evidence: vec![Evidence {
                offset: Some(section.offset),
                length: Some(section.size),
                value: section.name.clone(),
            }],
        });
    }

    if !indicators.is_empty() {
        findings.push(Finding {
            id: "embedded-indicators".into(),
            title: "Embedded network or execution indicators".into(),
            severity: Severity::Low,
            confidence: Confidence::Medium,
            rationale: "The sample contains strings that resemble network locations, commands, or registry paths.".into(),
            evidence: indicators
                .iter()
                .take(5)
                .map(|indicator| Evidence {
                    offset: Some(indicator.offset),
                    length: Some(indicator.value.len() as u64),
                    value: format!("{}: {}", indicator.kind, indicator.value),
                })
                .collect(),
        });
    }

    findings.push(Finding {
        id: "analysis-summary".into(),
        title: "Static analysis completed".into(),
        severity: Severity::Info,
        confidence: Confidence::High,
        rationale: "No sample instructions were executed; results are structural signals, not a malware verdict.".into(),
        evidence: vec![Evidence {
            offset: None,
            length: Some(sample_size as u64),
            value: "sample treated as inert bytes".into(),
        }],
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_oversized_inputs() {
        assert!(matches!(
            analyze("empty", &[], &AnalysisOptions::default()),
            Err(AnalysisError::Empty)
        ));
        let oversized = vec![0; MAX_INPUT_BYTES + 1];
        assert!(matches!(
            analyze("large", &oversized, &AnalysisOptions::default()),
            Err(AnalysisError::TooLarge { .. })
        ));
    }

    #[test]
    fn sanitizes_names_and_extracts_indicators() {
        let bytes = b"payload https://example.test/a 10.20.30.40 powershell.exe\0";
        let report = analyze("../bad\nname.bin", bytes, &AnalysisOptions::default()).unwrap();
        assert_eq!(report.sample.name, "badname.bin");
        assert!(report.indicators.iter().any(|item| item.kind == "url"));
        assert!(report.indicators.iter().any(|item| item.kind == "ipv4"));
    }

    #[test]
    fn report_is_serializable_and_deterministic_except_timing() {
        let bytes = b"MALWARE-LAB-TEST-DATA";
        let first = analyze("fixture.bin", bytes, &AnalysisOptions::default()).unwrap();
        let second = analyze("fixture.bin", bytes, &AnalysisOptions::default()).unwrap();
        assert_eq!(first.sample.sha256, second.sample.sha256);
        assert_eq!(first.findings.len(), second.findings.len());
        assert!(
            serde_json::to_string(&first)
                .unwrap()
                .contains("schema_version")
        );
    }

    #[test]
    fn string_limits_are_enforced() {
        let bytes = b"first\0second\0third\0fourth\0fifth\0";
        let report = analyze(
            "strings.bin",
            bytes,
            &AnalysisOptions {
                min_string_length: 4,
                max_strings: 3,
            },
        )
        .unwrap();
        assert_eq!(report.strings.len(), 3);
        assert!(report.stats.strings_truncated);
    }
}
