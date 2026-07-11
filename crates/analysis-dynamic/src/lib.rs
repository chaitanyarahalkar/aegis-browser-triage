mod api;
mod artifact;
mod cpu;
mod cpu64;
mod engine;
mod engine64;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixture;
mod generation;
mod loader;
mod loader64;
mod memory;
mod memory64;
mod model;
mod network;
mod provenance;
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
    OverlappingRegion { address: u64 },
    #[error("memory read failed at 0x{address:08x}")]
    MemoryRead { address: u64 },
    #[error("memory write failed at 0x{address:08x}")]
    MemoryWrite { address: u64 },
    #[error("instruction fetch failed at 0x{address:08x}")]
    MemoryExecute { address: u64 },
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
    let pe =
        goblin::pe::PE::parse(bytes).map_err(|error| DynamicError::InvalidPe(error.to_string()))?;
    if pe.is_64 {
        engine64::run(name.into(), bytes, options.clone().bounded())
    } else {
        engine::run(name.into(), bytes, options.clone().bounded())
    }
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
        assert!(
            matches!(report.termination, Termination::ExitProcess { code: 0 }),
            "unexpected termination: {:?}",
            report.termination
        );
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
        assert_eq!(report.schema_version, 14);
        assert_eq!(report.snapshots.first().unwrap().trigger, "entry");
        assert_eq!(report.snapshots.last().unwrap().trigger, "final");
        assert!(
            report
                .snapshots
                .iter()
                .all(|snapshot| snapshot.state_sha256.len() == 64)
        );
        assert_eq!(report.timeline.len(), report.api_calls.len());
        assert_eq!(report.timeline[2].category, "process");
        assert_eq!(report.coverage.modeled_api_calls, 4);
        assert_eq!(report.coverage.unmodeled_api_calls, 0);
        assert!(report.coverage.unique_instruction_addresses >= 8);
    }

    #[test]
    fn safe_pe64_executes_with_the_microsoft_x64_abi() {
        let bytes = fixture::safe_dynamic_pe64();
        let report = analyze_dynamic("safe64.exe", &bytes, &DynamicOptions::default()).unwrap();
        assert!(
            matches!(report.termination, Termination::ExitProcess { code: 0 }),
            "unexpected termination: {:?}",
            report.termination
        );
        assert_eq!(report.profile.architecture, "x86-64 (64-bit)");
        assert!(report.profile.image_base > u32::MAX as u64);
        assert_eq!(
            report
                .api_calls
                .iter()
                .map(|event| event.name.as_str())
                .collect::<Vec<_>>(),
            ["GetTickCount", "Sleep", "WinExec", "ExitProcess"]
        );
        assert_eq!(report.virtual_time_ms, 1_000_025);
        assert_eq!(report.snapshots[0].registers.rsp % 16, 8);
        assert_eq!(report.snapshots[0].registers.rcx, report.profile.image_base);
        assert_eq!(report.snapshots[0].registers.rdx, 1);
        assert_eq!(report.processes.len(), 1);
        assert!(report.processes[0].command.contains("x64.example.test"));
        assert_eq!(report.unwind_functions.len(), 1);
        assert!(
            report
                .system
                .iter()
                .any(|event| event.operation == "map_teb_peb")
        );
        assert!(
            report
                .instructions
                .iter()
                .any(|event| event.address == 0x0000_0001_4000_1150)
        );
        assert_eq!(report.schema_version, 14);
    }

    #[test]
    fn pe64_reports_are_deterministic_and_truncation_safe() {
        let bytes = fixture::safe_dynamic_pe64();
        let first = analyze_dynamic("safe64.exe", &bytes, &DynamicOptions::default()).unwrap();
        let second = analyze_dynamic("safe64.exe", &bytes, &DynamicOptions::default()).unwrap();
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        for length in 1..bytes.len() {
            let _ = analyze_dynamic(
                "truncated64.exe",
                &bytes[..length],
                &DynamicOptions {
                    max_instructions: 64,
                    max_trace_events: 16,
                    ..DynamicOptions::default()
                },
            );
        }
    }

    #[test]
    fn pe64_parity_fixture_exercises_artifacts_state_provenance_threads_and_exceptions() {
        let bytes = fixture::parity_dynamic_pe64();
        let analysis = analyze_dynamic_with_artifacts(
            "aegis-safe-parity-pe64.exe",
            &bytes,
            &DynamicOptions::default(),
        )
        .unwrap();
        let report = &analysis.report;
        assert!(
            matches!(report.termination, Termination::ExitProcess { code: 0 }),
            "unexpected termination: {:?}; apis: {:?}; last instruction: {:?}",
            report.termination,
            report
                .api_calls
                .iter()
                .map(|event| event.name.as_str())
                .collect::<Vec<_>>(),
            report.instructions.last()
        );
        assert!(
            report
                .filesystem
                .iter()
                .any(|event| event.operation == "write")
        );
        assert!(
            report
                .filesystem
                .iter()
                .any(|event| event.operation == "read")
        );
        assert!(report.registry.iter().any(|event| event.operation == "set"));
        assert!(
            report
                .registry
                .iter()
                .any(|event| event.operation == "query")
        );
        assert!(report.network.iter().any(|event| event.operation == "read"));
        assert!(
            report
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == ArtifactKind::Memory)
        );
        assert!(
            report
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == ArtifactKind::VirtualFile)
        );
        assert!(
            report
                .artifacts
                .iter()
                .any(|artifact| artifact.kind == ArtifactKind::NetworkDownload)
        );
        assert!(!report.payload_generations.is_empty());
        assert!(
            report
                .provenance_flows
                .iter()
                .any(|flow| flow.sink == ProvenanceSinkKind::VirtualFile)
        );
        assert!(
            report
                .provenance_flows
                .iter()
                .any(|flow| flow.sink == ProvenanceSinkKind::ProcessCommand)
        );
        assert!(
            report
                .provenance_sources
                .iter()
                .any(|source| { source.kind == ProvenanceSourceKind::VirtualFile })
        );
        assert!(
            report
                .provenance_sources
                .iter()
                .any(|source| { source.kind == ProvenanceSourceKind::Registry })
        );
        assert_eq!(report.threads.len(), 2);
        assert!(report.threads[1].instruction_count > 0);
        assert_eq!(report.threads[1].exit_code, Some(0x1338));
        assert!(
            report
                .thread_events
                .iter()
                .any(|event| event.operation == "created")
        );
        assert!(
            report
                .thread_events
                .iter()
                .any(|event| event.operation == "scheduled")
        );
        assert!(
            report
                .exceptions
                .iter()
                .any(|event| event.outcome == "continued_execution")
        );
        assert!(
            report
                .system
                .iter()
                .any(|event| event.operation == "runtime_function_lookup")
        );
        for artifact in &report.artifacts {
            assert!(analysis.artifact_bytes(&artifact.id).is_some());
        }
        let repeated = analyze_dynamic(
            "aegis-safe-parity-pe64.exe",
            &bytes,
            &DynamicOptions::default(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(report).unwrap(),
            serde_json::to_string(&repeated).unwrap()
        );
    }

    #[test]
    fn pe64_unpacks_generated_code_and_reconstructs_dynamic_imports() {
        let bytes = fixture::unpacking_dynamic_pe64();
        let analysis = analyze_dynamic_with_artifacts(
            "aegis-safe-unpacking-pe64.exe",
            &bytes,
            &DynamicOptions::default(),
        )
        .unwrap();
        let report = &analysis.report;
        assert!(matches!(
            report.termination,
            Termination::ExitProcess { code: 0 }
        ));
        assert_eq!(report.schema_version, 14);
        assert_eq!(report.coverage.dynamic_api_resolutions, 2);
        assert_eq!(report.virtual_time_ms, 1_000_025);
        assert!(
            report
                .api_calls
                .iter()
                .any(|event| event.name == "GetTickCount")
        );
        assert!(
            report
                .api_calls
                .iter()
                .any(|event| event.name == "GetCurrentProcessId")
        );
        let generation = report
            .payload_generations
            .iter()
            .find(|generation| generation.entry_point_candidate.is_some())
            .expect("generated executable stage");
        assert_eq!(
            generation.entry_point_candidate,
            Some(0x0000_0050_0000_0020)
        );
        assert_eq!(
            generation.reconstructed_imports,
            ["KERNEL32.dll!GetTickCount"]
        );
        assert!(generation.executed);
        assert!(generation.executable_heap);
        assert!(report.generation_stats.entry_point_candidates >= 1);
        assert_eq!(report.generation_stats.reconstructed_imports, 1);
        assert!(report.artifacts.iter().any(|artifact| {
            artifact.address == Some(0x0000_0050_0000_0000) && artifact.detected_format == "pe"
        }));
        assert!(report.system.iter().any(|event| {
            event.operation == "resolve_export" && event.target.contains("GetTickCount")
        }));
        assert!(report.system.iter().any(|event| {
            event.operation == "resolve_export" && event.target.contains("GetCurrentProcessId")
        }));
        let repeated = analyze_dynamic(
            "aegis-safe-unpacking-pe64.exe",
            &bytes,
            &DynamicOptions::default(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(report).unwrap(),
            serde_json::to_string(&repeated).unwrap()
        );
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
    fn runs_stateful_system_object_fixture() {
        let report = analyze_dynamic(
            "system.exe",
            &fixture::system_objects_pe32(),
            &DynamicOptions::default(),
        )
        .unwrap();
        assert!(matches!(
            report.termination,
            Termination::ExitProcess { code: 0 }
        ));
        assert!(
            report
                .system
                .iter()
                .any(|event| event.operation == "create_event")
        );
        let waits: Vec<_> = report
            .system
            .iter()
            .filter(|event| event.operation == "wait")
            .map(|event| event.result)
            .collect();
        assert_eq!(waits, [0x102, 0]);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id == "system-objects")
        );
    }

    #[test]
    fn runs_scripted_network_download_fixture() {
        let analysis = analyze_dynamic_with_artifacts(
            "network.exe",
            &fixture::network_scenario_pe32(),
            &DynamicOptions::default(),
        )
        .unwrap();
        assert!(matches!(
            analysis.report.termination,
            Termination::ExitProcess { code: 0 }
        ));
        assert_eq!(analysis.report.network_exchanges.len(), 2);
        assert!(analysis.report.provenance_sources.iter().any(|source| {
            source.kind == ProvenanceSourceKind::Network && source.api == "InternetReadFile"
        }));
        assert!(analysis.report.provenance_flows.iter().any(|flow| {
            flow.sink == ProvenanceSinkKind::ProcessCommand && flow.api == "WinExec"
        }));
        assert_eq!(
            analysis.report.network_exchanges[0].response_status,
            Some(302)
        );
        assert_eq!(analysis.report.network_exchanges[0].request_size, 0);
        assert_eq!(analysis.report.network_exchanges[1].response_size, 31);
        assert_eq!(
            analysis.report.network_exchanges[1]
                .response_sha256
                .as_deref()
                .map(str::len),
            Some(64)
        );
        let download = analysis
            .report
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == ArtifactKind::NetworkDownload)
            .unwrap();
        assert_eq!(
            analysis.artifact_bytes(&download.id).unwrap(),
            b"MZ AEGIS_SAFE_NETWORK_DOWNLOAD\0"
        );
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
