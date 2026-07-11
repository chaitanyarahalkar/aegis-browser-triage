mod api;
mod artifact;
mod cpu;
mod engine;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixture;
mod generation;
mod loader;
mod memory;
mod model;
mod windows;

pub use model::*;

use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug)]
pub struct DynamicAnalysis {
    pub report: DynamicReport,
    artifacts: BTreeMap<String, Vec<u8>>,
}

impl DynamicAnalysis {
    pub fn artifact_bytes(&self, id: &str) -> Option<&[u8]> {
        self.artifacts.get(id).map(Vec::as_slice)
    }
}

#[derive(Debug, Error)]
pub enum DynamicError {
    #[error("sample is empty")]
    Empty,
    #[error("sample exceeds the 128 MiB hard limit")]
    TooLarge,
    #[error("invalid PE: {0}")]
    InvalidPe(String),
    #[error("unsupported target: {0}")]
    UnsupportedTarget(String),
    #[error("dynamic memory limit exceeded")]
    MemoryLimit,
    #[error("memory region overlaps at 0x{address:08x}")]
    OverlappingRegion { address: u32 },
    #[error("memory read failed at 0x{address:08x}")]
    MemoryRead { address: u32 },
    #[error("memory write failed at 0x{address:08x}")]
    MemoryWrite { address: u32 },
    #[error("instruction fetch failed at 0x{address:08x}")]
    MemoryExecute { address: u32 },
    #[error("unsupported register {0}")]
    UnsupportedRegister(String),
    #[error("unsupported operand {0}")]
    UnsupportedOperand(String),
}

pub fn analyze_dynamic(
    name: impl Into<String>,
    bytes: &[u8],
    options: &DynamicOptions,
) -> Result<DynamicReport, DynamicError> {
    if bytes.is_empty() {
        return Err(DynamicError::Empty);
    }
    if bytes.len() > analysis_core_limit() {
        return Err(DynamicError::TooLarge);
    }
    Ok(analyze_dynamic_with_artifacts(name, bytes, options)?.report)
}

pub fn analyze_dynamic_with_artifacts(
    name: impl Into<String>,
    bytes: &[u8],
    options: &DynamicOptions,
) -> Result<DynamicAnalysis, DynamicError> {
    if bytes.is_empty() {
        return Err(DynamicError::Empty);
    }
    if bytes.len() > analysis_core_limit() {
        return Err(DynamicError::TooLarge);
    }
    engine::run(name.into(), bytes, options.clone().bounded())
}

const fn analysis_core_limit() -> usize {
    128 * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_pe_executes_modeled_windows_apis() {
        let bytes = fixture::safe_dynamic_pe32();
        let report = analyze_dynamic("safe.exe", &bytes, &DynamicOptions::default()).unwrap();
        assert!(matches!(
            report.termination,
            Termination::ExitProcess { code: 0 }
        ));
        assert_eq!(
            report
                .api_calls
                .iter()
                .map(|event| event.name.as_str())
                .collect::<Vec<_>>(),
            ["GetTickCount", "Sleep", "WinExec", "ExitProcess"]
        );
        assert_eq!(report.virtual_time_ms, 1_000_025);
        assert_eq!(report.processes.len(), 1);
        assert!(report.processes[0].command.contains("powershell.exe"));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "process-execution")
        );
        assert!(
            report
                .api_calls
                .iter()
                .any(|event| event.summary.contains("powershell.exe"))
        );
        assert!(report.instruction_count >= 8);
        assert_eq!(report.schema_version, 8);
        assert_eq!(report.timeline.len(), report.api_calls.len());
        assert_eq!(report.timeline[2].category, "process");
        assert_eq!(report.coverage.modeled_api_calls, 4);
        assert_eq!(report.coverage.unmodeled_api_calls, 0);
        assert!(report.coverage.unique_instruction_addresses >= 8);
    }

    #[test]
    fn reports_are_deterministic() {
        let bytes = fixture::safe_dynamic_pe32();
        let first = analyze_dynamic("safe.exe", &bytes, &DynamicOptions::default()).unwrap();
        let second = analyze_dynamic("safe.exe", &bytes, &DynamicOptions::default()).unwrap();
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }

    #[test]
    fn environment_profiles_produce_deterministic_run_variants() {
        let bytes = fixture::safe_dynamic_pe32();
        let balanced = analyze_dynamic("safe.exe", &bytes, &DynamicOptions::default()).unwrap();
        let hardened_options = DynamicOptions {
            environment: EnvironmentProfile::hardened(),
            ..DynamicOptions::default()
        };
        let hardened = analyze_dynamic("safe.exe", &bytes, &hardened_options).unwrap();
        let hardened_again = analyze_dynamic("safe.exe", &bytes, &hardened_options).unwrap();
        assert_eq!(hardened.profile.environment.id, "hardened");
        assert_eq!(
            hardened.profile.environment.network_mode,
            NetworkMode::Offline
        );
        assert_ne!(balanced.api_calls[0].result, hardened.api_calls[0].result);
        assert_eq!(
            serde_json::to_string(&hardened).unwrap(),
            serde_json::to_string(&hardened_again).unwrap()
        );
    }

    #[test]
    fn executes_a_dynamically_resolved_api() {
        let bytes = fixture::dynamic_resolution_pe32();
        let report =
            analyze_dynamic("dynamic-api.exe", &bytes, &DynamicOptions::default()).unwrap();
        assert!(matches!(
            report.termination,
            Termination::ExitProcess { code: 0 }
        ));
        assert_eq!(report.coverage.dynamic_api_resolutions, 1);
        assert_eq!(
            report
                .api_calls
                .iter()
                .map(|event| event.name.as_str())
                .collect::<Vec<_>>(),
            [
                "LoadLibraryA",
                "GetProcAddress",
                "GetCurrentProcessId",
                "ExitProcess"
            ]
        );
        assert!(
            report
                .timeline
                .iter()
                .any(|event| event.subject.contains("Resolved dynamic symbol"))
        );
    }

    #[test]
    fn captures_runtime_memory_and_virtual_file_artifacts() {
        let bytes = fixture::runtime_artifact_pe32();
        let analysis =
            analyze_dynamic_with_artifacts("artifact.exe", &bytes, &DynamicOptions::default())
                .unwrap();
        assert!(matches!(
            analysis.report.termination,
            Termination::ExitProcess { code: 0 }
        ));
        assert!(
            analysis
                .report
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == ArtifactKind::Memory
                    && artifact.trigger == "executable_transition")
        );
        assert!(
            analysis
                .report
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == ArtifactKind::VirtualFile)
        );
        assert!(analysis.report.payload_generations.len() >= 2);
        assert!(
            analysis
                .report
                .payload_generations
                .iter()
                .any(|generation| generation.parent_id.is_some())
        );
        assert!(
            analysis
                .report
                .payload_generations
                .iter()
                .any(|generation| generation.executed && generation.executable_heap)
        );
        assert!(
            analysis
                .report
                .findings
                .iter()
                .any(|finding| finding.id == "payload-generations")
        );
        for artifact in &analysis.report.artifacts {
            assert!(analysis.artifact_bytes(&artifact.id).is_some());
        }
        let json = serde_json::to_string(&analysis.report).unwrap();
        assert!(!json.contains("\"bytes\":["));
    }

    #[test]
    fn dispatches_breakpoint_through_guest_seh_and_continues() {
        let report =
            analyze_dynamic("seh.exe", &fixture::seh_pe32(), &DynamicOptions::default()).unwrap();
        assert!(matches!(
            report.termination,
            Termination::ExitProcess { code: 0 }
        ));
        assert_eq!(report.exceptions.len(), 1);
        assert_eq!(report.exceptions[0].code, 0x8000_0003);
        assert_eq!(report.exceptions[0].outcome, "continued_execution");
        assert_eq!(report.exceptions[0].disposition, Some(-1));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "exception-dispatch")
        );
    }

    #[test]
    fn schedules_a_guest_thread_with_isolated_cpu_stack_and_teb() {
        let report = analyze_dynamic(
            "threads.exe",
            &fixture::threads_pe32(),
            &DynamicOptions::default(),
        )
        .unwrap();
        assert!(matches!(
            report.termination,
            Termination::ExitProcess { code: 0 }
        ));
        assert_eq!(report.threads.len(), 2);
        let child = report
            .threads
            .iter()
            .find(|thread| thread.tid == 2)
            .unwrap();
        assert_eq!(child.state, "terminated");
        assert_eq!(child.exit_code, Some(42));
        assert!(
            report
                .thread_events
                .iter()
                .any(|event| event.tid == 2 && event.operation == "scheduled")
        );
        assert!(
            report
                .thread_events
                .iter()
                .any(|event| event.tid == 2 && event.operation == "exited")
        );
    }

    #[test]
    fn runs_extended_integer_sse2_and_x87_fixture() {
        let report = analyze_dynamic(
            "instructions.exe",
            &fixture::instruction_coverage_pe32(),
            &DynamicOptions::default(),
        )
        .unwrap();
        assert!(matches!(
            report.termination,
            Termination::ExitProcess { code: 0 }
        ));
        assert!(report.diagnostics.first_unsupported.is_none());
        for mnemonic in ["addss", "bts", "bsf", "faddp", "fstp"] {
            assert!(
                report
                    .instructions
                    .iter()
                    .any(|event| event.text.starts_with(mnemonic)),
                "missing {mnemonic}"
            );
        }
    }

    #[test]
    fn instruction_limit_stops_infinite_loop() {
        let mut bytes = fixture::safe_dynamic_pe32();
        bytes[0x200..0x202].copy_from_slice(&[0xeb, 0xfe]);
        let report = analyze_dynamic(
            "loop.exe",
            &bytes,
            &DynamicOptions {
                max_instructions: 25,
                max_trace_events: 10,
                ..DynamicOptions::default()
            },
        )
        .unwrap();
        assert!(matches!(report.termination, Termination::InstructionLimit));
        assert_eq!(report.instruction_count, 25);
        assert_eq!(report.instructions.len(), 10);
        assert!(report.truncated);
    }

    #[test]
    fn invalid_memory_access_becomes_a_bounded_termination() {
        let mut bytes = fixture::safe_dynamic_pe32();
        bytes[0x200..0x205].copy_from_slice(&[0xa1, 0xff, 0xff, 0xff, 0xff]);
        let report = analyze_dynamic("fault.exe", &bytes, &DynamicOptions::default()).unwrap();
        assert!(matches!(
            report.termination,
            Termination::MemoryFault {
                address: 0xffff_ffff,
                ..
            }
        ));
    }

    #[test]
    fn rejects_non_pe32_targets() {
        let error =
            analyze_dynamic("wasm", b"\0asm\x01\0\0\0", &DynamicOptions::default()).unwrap_err();
        assert!(matches!(error, DynamicError::InvalidPe(_)));
    }
}
