fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "safe-dynamic-pe32.exe".into());
    let bytes = if std::env::args().any(|argument| argument == "--linux") {
        analysis_dynamic::fixture::safe_dynamic_elf64()
    } else if std::env::args().any(|argument| argument == "--code-analysis") {
        analysis_dynamic::fixture::code_analysis_pe64()
    } else if std::env::args().any(|argument| argument == "--x64-unpacking") {
        analysis_dynamic::fixture::unpacking_dynamic_pe64()
    } else if std::env::args().any(|argument| argument == "--x64-parity") {
        analysis_dynamic::fixture::parity_dynamic_pe64()
    } else if std::env::args().any(|argument| argument == "--x64") {
        analysis_dynamic::fixture::safe_dynamic_pe64()
    } else if std::env::args().any(|argument| argument == "--artifact") {
        analysis_dynamic::fixture::runtime_artifact_pe32()
    } else if std::env::args().any(|argument| argument == "--seh") {
        analysis_dynamic::fixture::seh_pe32()
    } else if std::env::args().any(|argument| argument == "--threads") {
        analysis_dynamic::fixture::threads_pe32()
    } else if std::env::args().any(|argument| argument == "--instructions") {
        analysis_dynamic::fixture::instruction_coverage_pe32()
    } else if std::env::args().any(|argument| argument == "--system") {
        analysis_dynamic::fixture::system_objects_pe32()
    } else if std::env::args().any(|argument| argument == "--network") {
        analysis_dynamic::fixture::network_scenario_pe32()
    } else {
        analysis_dynamic::fixture::safe_dynamic_pe32()
    };
    std::fs::write(&path, bytes).unwrap();
    println!("wrote {path}");
}
