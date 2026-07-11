use analysis_core::{AnalysisOptions, BinaryFormat, FormatReport, analyze};
use std::time::Instant;

#[test]
fn parses_minimal_pe64_and_detects_wx_section() {
    let report = analyze("fixture.exe", &minimal_pe64(), &AnalysisOptions::default()).unwrap();
    assert_eq!(report.sample.detected_format, BinaryFormat::Pe);
    assert!(matches!(
        report.format,
        FormatReport::Pe { bitness: 64, .. }
    ));
    assert_eq!(report.sections.len(), 1);
    assert_eq!(report.sections[0].name, ".text");
    assert_eq!(report.sections[0].permissions, "rwx");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.id == "writable-executable-section")
    );
}

#[test]
fn parses_minimal_elf64() {
    let report = analyze("fixture.elf", &minimal_elf64(), &AnalysisOptions::default()).unwrap();
    assert_eq!(report.sample.detected_format, BinaryFormat::Elf);
    assert!(matches!(
        report.format,
        FormatReport::Elf { bitness: 64, .. }
    ));
    assert!(
        report
            .sample
            .architecture
            .as_deref()
            .unwrap_or_default()
            .contains("X86_64")
    );
}

#[test]
fn parses_minimal_macho64() {
    let report = analyze(
        "fixture.macho",
        &minimal_macho64(),
        &AnalysisOptions::default(),
    )
    .unwrap();
    assert_eq!(report.sample.detected_format, BinaryFormat::MachO);
    assert!(matches!(
        report.format,
        FormatReport::MachO {
            bitness: Some(64),
            ..
        }
    ));
}

#[test]
fn parses_wasm_function_and_export() {
    let wasm = [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03,
        0x02, 0x01, 0x00, 0x07, 0x08, 0x01, 0x04, b'm', b'a', b'i', b'n', 0x00, 0x00, 0x0a, 0x04,
        0x01, 0x02, 0x00, 0x0b,
    ];
    let report = analyze("fixture.wasm", &wasm, &AnalysisOptions::default()).unwrap();
    assert_eq!(report.sample.detected_format, BinaryFormat::WebAssembly);
    assert_eq!(report.exports[0].name, "main");
    assert!(matches!(
        report.format,
        FormatReport::WebAssembly {
            valid: true,
            functions: 1,
            ..
        }
    ));
}

#[test]
fn every_truncated_prefix_fails_without_panicking() {
    for fixture in [minimal_pe64(), minimal_elf64(), minimal_macho64()] {
        for length in 1..fixture.len() {
            let _ = analyze(
                "truncated.bin",
                &fixture[..length],
                &AnalysisOptions::default(),
            );
        }
    }
}

#[test]
fn multi_megabyte_unknown_sample_stays_within_a_generous_budget() {
    let bytes = vec![0x41; 4 * 1024 * 1024];
    let started = Instant::now();
    let report = analyze("large.bin", &bytes, &AnalysisOptions::default()).unwrap();
    assert_eq!(report.sample.size, bytes.len() as u64);
    assert!(
        started.elapsed().as_secs_f32() < 5.0,
        "analysis took {:?}",
        started.elapsed()
    );
}

#[test]
fn parses_the_real_host_test_binary() {
    let path = std::env::current_exe().unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let report = analyze(
        path.file_name().unwrap().to_string_lossy(),
        &bytes,
        &AnalysisOptions::default(),
    )
    .unwrap();
    assert_ne!(report.sample.detected_format, BinaryFormat::Unknown);
    assert!(!report.sections.is_empty());
    assert_eq!(report.sample.size, bytes.len() as u64);
}

fn minimal_pe64() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x84, 0x8664);
    put_u16(&mut bytes, 0x86, 1);
    put_u32(&mut bytes, 0x88, 0x65aa_5500);
    put_u16(&mut bytes, 0x94, 0xf0);
    put_u16(&mut bytes, 0x96, 0x0022);
    let optional = 0x98;
    put_u16(&mut bytes, optional, 0x20b);
    put_u32(&mut bytes, optional + 4, 0x200);
    put_u32(&mut bytes, optional + 16, 0x1000);
    put_u32(&mut bytes, optional + 20, 0x1000);
    put_u64(&mut bytes, optional + 24, 0x1_4000_0000);
    put_u32(&mut bytes, optional + 32, 0x1000);
    put_u32(&mut bytes, optional + 36, 0x200);
    put_u16(&mut bytes, optional + 40, 6);
    put_u16(&mut bytes, optional + 48, 6);
    put_u32(&mut bytes, optional + 56, 0x2000);
    put_u32(&mut bytes, optional + 60, 0x200);
    put_u16(&mut bytes, optional + 68, 3);
    put_u16(&mut bytes, optional + 70, 0x8160);
    put_u64(&mut bytes, optional + 72, 0x10_0000);
    put_u64(&mut bytes, optional + 80, 0x1000);
    put_u64(&mut bytes, optional + 88, 0x10_0000);
    put_u64(&mut bytes, optional + 96, 0x1000);
    put_u32(&mut bytes, optional + 108, 16);
    let section = optional + 0xf0;
    bytes[section..section + 5].copy_from_slice(b".text");
    put_u32(&mut bytes, section + 8, 0x200);
    put_u32(&mut bytes, section + 12, 0x1000);
    put_u32(&mut bytes, section + 16, 0x200);
    put_u32(&mut bytes, section + 20, 0x200);
    put_u32(&mut bytes, section + 36, 0xe000_0020);
    for (index, byte) in bytes[0x200..0x400].iter_mut().enumerate() {
        *byte = index as u8;
    }
    bytes
}

fn minimal_elf64() -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 0x3e);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 24, 0x400000);
    put_u16(&mut bytes, 52, 64);
    put_u16(&mut bytes, 54, 56);
    put_u16(&mut bytes, 58, 64);
    bytes
}

fn minimal_macho64() -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    put_u32(&mut bytes, 0, 0xfeed_facf);
    put_u32(&mut bytes, 4, 0x0100_0007);
    put_u32(&mut bytes, 8, 3);
    put_u32(&mut bytes, 12, 2);
    bytes
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
