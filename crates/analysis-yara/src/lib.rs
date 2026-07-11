mod engine;
mod model;

pub use engine::*;
pub use model::*;

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
rule demo : test {
  meta:
    severity = "critical"
    description = "test rule"
  strings:
    $text = "powershell.exe" nocase
    $hex = { 68 74 74 70 }
  condition:
    all of them
}
"#;

    #[test]
    fn compiles_and_reports_exact_matches() {
        let compiled = CompiledYaraRules::compile("Tests", "test.yar", "tests", RULES).unwrap();
        let report = compiled
            .scan(
                "sample.bin",
                b"powershell.exe https",
                &YaraScanOptions::default(),
            )
            .unwrap();
        assert_eq!(compiled.summary().rule_count, 1);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].severity, "high");
        assert_eq!(report.matches[0].patterns.len(), 2);
        assert_eq!(report.stats.reported_occurrences, 2);
        assert_eq!(report.matches[0].patterns[0].occurrences[0].offset, 0);
    }

    #[test]
    fn compilation_errors_are_structured() {
        let error = CompiledYaraRules::compile("Bad", "bad.yar", "custom", "rule broken {")
            .err()
            .expect("invalid source should fail");
        assert!(!error.errors.is_empty());
        assert!(error.errors[0].details.is_object());
    }

    #[test]
    fn includes_and_disabled_modules_are_rejected() {
        assert!(
            CompiledYaraRules::compile("Bad", "bad.yar", "custom", "include \"other.yar\"")
                .is_err()
        );
        assert!(
            CompiledYaraRules::compile(
                "Bad",
                "bad.yar",
                "custom",
                "import \"cuckoo\" rule x { condition: true }"
            )
            .is_err()
        );
    }

    #[test]
    fn source_and_match_limits_are_bounded() {
        let oversized = "a".repeat(MAX_RULE_SOURCE_BYTES + 1);
        assert!(CompiledYaraRules::compile("Large", "large.yar", "custom", &oversized).is_err());
        let compiled = CompiledYaraRules::compile(
            "Limits",
            "limits.yar",
            "custom",
            "rule repeated { strings: $a = \"AAAA\" condition: $a }",
        )
        .unwrap();
        let report = compiled
            .scan(
                "many.bin",
                b"AAAAAAAAAAAA",
                &YaraScanOptions {
                    max_matches_per_pattern: 2,
                    max_reported_matches: 2,
                },
            )
            .unwrap();
        assert_eq!(report.stats.reported_occurrences, 2);
    }
}
