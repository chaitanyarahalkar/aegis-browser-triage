//! Deterministic, harmless PE32 fixture used by tests and the browser demo.

pub fn safe_dynamic_pe32() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x600];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

    // COFF header.
    put_u16(&mut bytes, 0x84, 0x014c);
    put_u16(&mut bytes, 0x86, 2);
    put_u32(&mut bytes, 0x88, 0x66aa_5500);
    put_u16(&mut bytes, 0x94, 0x00e0);
    put_u16(&mut bytes, 0x96, 0x0102);

    // PE32 optional header.
    let optional = 0x98;
    put_u16(&mut bytes, optional, 0x010b);
    bytes[optional + 2] = 14;
    put_u32(&mut bytes, optional + 4, 0x200);
    put_u32(&mut bytes, optional + 8, 0x200);
    put_u32(&mut bytes, optional + 16, 0x1000);
    put_u32(&mut bytes, optional + 20, 0x1000);
    put_u32(&mut bytes, optional + 24, 0x2000);
    put_u32(&mut bytes, optional + 28, 0x0040_0000);
    put_u32(&mut bytes, optional + 32, 0x1000);
    put_u32(&mut bytes, optional + 36, 0x200);
    put_u16(&mut bytes, optional + 40, 6);
    put_u16(&mut bytes, optional + 48, 6);
    put_u32(&mut bytes, optional + 56, 0x3000);
    put_u32(&mut bytes, optional + 60, 0x200);
    put_u16(&mut bytes, optional + 68, 3);
    put_u16(&mut bytes, optional + 70, 0x0140);
    put_u32(&mut bytes, optional + 72, 0x10_0000);
    put_u32(&mut bytes, optional + 76, 0x1000);
    put_u32(&mut bytes, optional + 80, 0x10_0000);
    put_u32(&mut bytes, optional + 84, 0x1000);
    put_u32(&mut bytes, optional + 92, 16);
    // Import and IAT directories.
    put_u32(&mut bytes, optional + 104, 0x2000);
    put_u32(&mut bytes, optional + 108, 0x28);
    put_u32(&mut bytes, optional + 192, 0x2060);
    put_u32(&mut bytes, optional + 196, 0x14);

    let text_section = optional + 0xe0;
    write_section(
        &mut bytes,
        text_section,
        b".text",
        (0x200, 0x1000, 0x200, 0x200, 0x6000_0020),
    );
    write_section(
        &mut bytes,
        text_section + 40,
        b".idata",
        (0x200, 0x2000, 0x200, 0x400, 0xc000_0040),
    );

    // Entry point: call deterministic APIs, request a process execution, exit.
    let code = [
        0xff, 0x15, 0x60, 0x20, 0x40, 0x00, // call [GetTickCount]
        0x6a, 0x19, // push 25
        0xff, 0x15, 0x64, 0x20, 0x40, 0x00, // call [Sleep]
        0x6a, 0x01, // push SW_SHOWNORMAL
        0x68, 0x00, 0x11, 0x40, 0x00, // push command string
        0xff, 0x15, 0x68, 0x20, 0x40, 0x00, // call [WinExec]
        0x6a, 0x00, // push 0
        0xff, 0x15, 0x6c, 0x20, 0x40, 0x00, // call [ExitProcess]
        0xcc, // int3 fallback
    ];
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    let command = b"powershell.exe -NoProfile https://example.test 10.20.30.40\0";
    bytes[0x300..0x300 + command.len()].copy_from_slice(command);

    // Import descriptor, lookup table, IAT, DLL name, and hint/name records.
    put_u32(&mut bytes, 0x400, 0x2040);
    put_u32(&mut bytes, 0x40c, 0x2080);
    put_u32(&mut bytes, 0x410, 0x2060);
    for (index, name_rva) in [0x2090, 0x20a0, 0x20a8, 0x20b4, 0].into_iter().enumerate() {
        put_u32(&mut bytes, 0x440 + index * 4, name_rva);
        put_u32(&mut bytes, 0x460 + index * 4, name_rva);
    }
    write_c_string(&mut bytes, 0x480, b"KERNEL32.dll");
    write_hint_name(&mut bytes, 0x490, b"GetTickCount");
    write_hint_name(&mut bytes, 0x4a0, b"Sleep");
    write_hint_name(&mut bytes, 0x4a8, b"WinExec");
    write_hint_name(&mut bytes, 0x4b4, b"ExitProcess");
    bytes
}

fn write_section(bytes: &mut [u8], offset: usize, name: &[u8], layout: (u32, u32, u32, u32, u32)) {
    let (virtual_size, virtual_address, raw_size, raw_offset, characteristics) = layout;
    bytes[offset..offset + name.len().min(8)].copy_from_slice(&name[..name.len().min(8)]);
    put_u32(bytes, offset + 8, virtual_size);
    put_u32(bytes, offset + 12, virtual_address);
    put_u32(bytes, offset + 16, raw_size);
    put_u32(bytes, offset + 20, raw_offset);
    put_u32(bytes, offset + 36, characteristics);
}

fn write_hint_name(bytes: &mut [u8], offset: usize, value: &[u8]) {
    put_u16(bytes, offset, 0);
    write_c_string(bytes, offset + 2, value);
}

fn write_c_string(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes[offset..offset + value.len()].copy_from_slice(value);
    bytes[offset + value.len()] = 0;
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
