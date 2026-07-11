use crate::{
    ArtifactIndicator, ArtifactKind, ArtifactOrigin, ArtifactStats, ArtifactString, ArtifactSummary,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_ARTIFACTS: usize = 128;
pub const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TOTAL_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;
const MAX_ORIGINS: usize = 16;
const MAX_STRINGS: usize = 256;

#[derive(Debug, Default)]
pub struct ArtifactStore {
    summaries: Vec<ArtifactSummary>,
    blobs: BTreeMap<String, Vec<u8>>,
    retained_bytes: usize,
    truncated: bool,
}

pub struct ArtifactCapture<'a> {
    pub kind: ArtifactKind,
    pub name: String,
    pub trigger: &'a str,
    pub address: Option<u64>,
    pub path: Option<String>,
    pub permissions: Option<String>,
    pub force: bool,
}

impl ArtifactStore {
    pub fn capture(
        &mut self,
        request: ArtifactCapture<'_>,
        bytes: &[u8],
        origin: ArtifactOrigin,
    ) -> Option<String> {
        if bytes.is_empty() {
            return None;
        }
        let captured = &bytes[..bytes.len().min(MAX_ARTIFACT_BYTES)];
        if !request.force && !interesting(captured, request.permissions.as_deref()) {
            return None;
        }
        let id = hex::encode(Sha256::digest(captured));
        if let Some(summary) = self.summaries.iter_mut().find(|item| item.id == id) {
            if summary.origins.len() < MAX_ORIGINS {
                summary.origins.push(origin);
            } else {
                summary.truncated = true;
            }
            return Some(id);
        }
        if self.summaries.len() >= MAX_ARTIFACTS
            || self.retained_bytes.saturating_add(captured.len()) > MAX_TOTAL_ARTIFACT_BYTES
        {
            self.truncated = true;
            return None;
        }
        let strings = extract_strings(captured);
        let indicators = extract_indicators(&strings);
        let summary = ArtifactSummary {
            id: id.clone(),
            kind: request.kind,
            name: sanitize_name(&request.name),
            size: bytes.len() as u64,
            captured_size: captured.len() as u64,
            sha256: id.clone(),
            entropy: entropy(captured),
            detected_format: detect_format(captured).into(),
            trigger: request.trigger.into(),
            address: request.address,
            path: request.path,
            permissions: request.permissions,
            strings,
            indicators,
            origins: vec![origin],
            truncated: captured.len() != bytes.len(),
        };
        self.retained_bytes += captured.len();
        self.blobs.insert(id.clone(), captured.to_vec());
        self.summaries.push(summary);
        Some(id)
    }

    pub fn finish(
        mut self,
    ) -> (
        Vec<ArtifactSummary>,
        ArtifactStats,
        BTreeMap<String, Vec<u8>>,
    ) {
        self.summaries
            .sort_by(|a, b| a.kind.cmp(&b.kind).then(a.name.cmp(&b.name)));
        let stats = ArtifactStats {
            count: self.summaries.len(),
            retained_bytes: self.retained_bytes as u64,
            truncated: self.truncated,
        };
        (self.summaries, stats, self.blobs)
    }
}

fn interesting(bytes: &[u8], permissions: Option<&str>) -> bool {
    permissions.is_some_and(|value| value.contains('x'))
        || detect_format(bytes) != "unknown"
        || (bytes.len() >= 256 && entropy(bytes) >= 6.5)
        || signal_count(bytes) >= 2
}

fn signal_count(bytes: &[u8]) -> usize {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    [
        "http://",
        "https://",
        "powershell",
        "currentversion\\run",
        "cmd.exe",
        "user-agent",
    ]
    .iter()
    .filter(|needle| lower.contains(**needle))
    .count()
}

fn detect_format(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"MZ") {
        "pe"
    } else if bytes.starts_with(b"\x7fELF") {
        "elf"
    } else if bytes.starts_with(b"\0asm") {
        "web_assembly"
    } else if bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
    {
        "mach_o"
    } else {
        "unknown"
    }
}

fn entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn extract_strings(bytes: &[u8]) -> Vec<ArtifactString> {
    let mut result = Vec::new();
    let mut start = 0;
    while start < bytes.len() && result.len() < MAX_STRINGS {
        if matches!(bytes[start], b' '..=b'~') {
            let mut end = start + 1;
            while end < bytes.len() && matches!(bytes[end], b' '..=b'~') && end - start < 512 {
                end += 1;
            }
            if end - start >= 4 {
                result.push(ArtifactString {
                    offset: start as u64,
                    encoding: "ascii".into(),
                    value: String::from_utf8_lossy(&bytes[start..end]).into_owned(),
                });
            }
            start = end;
        } else {
            start += 1;
        }
    }
    result
}

fn extract_indicators(strings: &[ArtifactString]) -> Vec<ArtifactIndicator> {
    strings
        .iter()
        .filter_map(|item| {
            let lower = item.value.to_ascii_lowercase();
            let kind = if lower.contains("http://") || lower.contains("https://") {
                "url"
            } else if lower.contains("currentversion\\run") {
                "registry"
            } else if lower.contains("powershell") || lower.contains("cmd.exe") {
                "command"
            } else {
                return None;
            };
            Some(ArtifactIndicator {
                kind: kind.into(),
                value: item.value.clone(),
                offset: item.offset,
            })
        })
        .take(128)
        .collect()
}

fn sanitize_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .filter(|character| !character.is_control())
        .take(160)
        .collect();
    if clean.is_empty() {
        "artifact.bin".into()
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> ArtifactOrigin {
        ArtifactOrigin {
            api: "VirtualProtect".into(),
            instruction: 10,
            virtual_time_ms: 1_000,
            timeline_sequence: Some(2),
            trigger: "executable_transition".into(),
            address: Some(0x1000),
            path: None,
        }
    }

    #[test]
    fn deduplicates_bytes_and_never_embeds_them_in_summaries() {
        let mut store = ArtifactStore::default();
        let bytes = b"MZ harmless runtime artifact marker";
        let first = store
            .capture(
                ArtifactCapture {
                    kind: ArtifactKind::Memory,
                    name: "one".into(),
                    trigger: "test",
                    address: Some(0x1000),
                    path: None,
                    permissions: Some("r-x".into()),
                    force: true,
                },
                bytes,
                origin(),
            )
            .unwrap();
        let second = store
            .capture(
                ArtifactCapture {
                    kind: ArtifactKind::VirtualFile,
                    name: "two".into(),
                    trigger: "test",
                    address: None,
                    path: Some("C:\\two".into()),
                    permissions: None,
                    force: true,
                },
                bytes,
                origin(),
            )
            .unwrap();
        assert_eq!(first, second);
        let (summaries, stats, blobs) = store.finish();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].origins.len(), 2);
        assert_eq!(stats.count, 1);
        assert_eq!(blobs[&first], bytes);
        assert!(
            !serde_json::to_string(&summaries)
                .unwrap()
                .contains("\"bytes\"")
        );
    }
}
