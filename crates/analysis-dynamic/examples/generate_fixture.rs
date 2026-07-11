fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "safe-dynamic-pe32.exe".into());
    std::fs::write(&path, analysis_dynamic::fixture::safe_dynamic_pe32()).unwrap();
    println!("wrote {path}");
}
