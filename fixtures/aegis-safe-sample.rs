// Harmless local fixture for testing Aegis static analysis.
// These strings are intentionally suspicious-looking but are never used.
const TEST_INDICATORS: &[&str] = &[
    "https://example.test/payload",
    "10.20.30.40",
    "powershell.exe -NoProfile",
    "HKEY_CURRENT_USER\\Software\\AegisSafeFixture",
];

fn main() {
    println!("Aegis safe test fixture: {} inert indicators embedded", TEST_INDICATORS.len());
}
