fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "safe-dynamic-pe32.exe".into());
    let bytes = if std::env::args().any(|argument| argument == "--artifact") {
        analysis_dynamic::fixture::runtime_artifact_pe32()
    } else {
        analysis_dynamic::fixture::safe_dynamic_pe32()
    };
    std::fs::write(&path, bytes).unwrap();
    println!("wrote {path}");
}
