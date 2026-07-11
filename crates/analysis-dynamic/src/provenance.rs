use crate::{
    ProvenanceFlow, ProvenanceSinkKind, ProvenanceSource, ProvenanceSourceKind, ProvenanceStats,
};
use std::collections::BTreeSet;

const MAX_SOURCES: usize = 256;
const MAX_FLOWS: usize = 4_096;
const MAX_RANGES: usize = 4_096;
const MAX_LABELS_PER_RANGE: usize = 8;

#[derive(Debug, Clone)]
struct TaintRange {
    start: u32,
    end: u32,
    labels: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ProvenanceTracker {
    sources: Vec<ProvenanceSource>,
    flows: Vec<ProvenanceFlow>,
    ranges: Vec<TaintRange>,
    truncated: bool,
}

impl ProvenanceTracker {
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    pub fn flow_evidence(&self) -> Vec<String> {
        self.flows
            .iter()
            .take(20)
            .map(|flow| {
                format!(
                    "{} -> {:?} {} via {}",
                    flow.source_ids.join(" + "),
                    flow.sink,
                    flow.destination,
                    flow.api
                )
            })
            .collect()
    }

    pub fn source(
        &mut self,
        kind: ProvenanceSourceKind,
        label: impl Into<String>,
        address: u32,
        size: usize,
        api: impl Into<String>,
        instruction: u64,
    ) -> Option<String> {
        self.source_with_parents(kind, label, address, size, api, instruction, Vec::new())
    }

    pub fn derive(
        &mut self,
        source_address: u32,
        destination: u32,
        size: usize,
        label: impl Into<String>,
        api: impl Into<String>,
        instruction: u64,
    ) -> Option<String> {
        self.derive_sized(
            source_address,
            size,
            destination,
            size,
            label,
            api,
            instruction,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn derive_sized(
        &mut self,
        source_address: u32,
        source_size: usize,
        destination: u32,
        destination_size: usize,
        label: impl Into<String>,
        api: impl Into<String>,
        instruction: u64,
    ) -> Option<String> {
        let parents = self.labels_for(source_address, source_size);
        self.source_with_parents(
            ProvenanceSourceKind::Transformation,
            label,
            destination,
            destination_size,
            api,
            instruction,
            parents,
        )
    }

    pub fn propagate(&mut self, source: u32, destination: u32, size: usize) {
        if size == 0 {
            return;
        }
        let labels = self.labels_for(source, size);
        self.replace_range(destination, size, labels);
    }

    pub fn clear(&mut self, address: u32, size: usize) {
        self.replace_range(address, size, Vec::new());
    }

    pub fn observe(
        &mut self,
        address: u32,
        size: usize,
        sink: ProvenanceSinkKind,
        destination: impl Into<String>,
        api: impl Into<String>,
        instruction: u64,
    ) {
        let source_ids = self.labels_for(address, size);
        if source_ids.is_empty() {
            return;
        }
        if self.flows.len() >= MAX_FLOWS {
            self.truncated = true;
            return;
        }
        self.flows.push(ProvenanceFlow {
            sequence: self.flows.len() as u64,
            source_ids,
            sink,
            destination: destination.into(),
            address: address.into(),
            size: size as u64,
            api: api.into(),
            instruction,
        });
    }

    pub fn finish(self) -> (Vec<ProvenanceSource>, Vec<ProvenanceFlow>, ProvenanceStats) {
        let stats = ProvenanceStats {
            source_count: self.sources.len(),
            flow_count: self.flows.len(),
            tracked_ranges: self.ranges.len(),
            truncated: self.truncated,
        };
        (self.sources, self.flows, stats)
    }

    #[allow(clippy::too_many_arguments)]
    fn source_with_parents(
        &mut self,
        kind: ProvenanceSourceKind,
        label: impl Into<String>,
        address: u32,
        size: usize,
        api: impl Into<String>,
        instruction: u64,
        parent_ids: Vec<String>,
    ) -> Option<String> {
        if size == 0 {
            return None;
        }
        if self.sources.len() >= MAX_SOURCES {
            self.truncated = true;
            return None;
        }
        let id = format!("source-{:04}", self.sources.len() + 1);
        self.sources.push(ProvenanceSource {
            id: id.clone(),
            kind,
            label: label.into(),
            address: address.into(),
            size: size as u64,
            api: api.into(),
            instruction,
            parent_ids,
        });
        self.replace_range(address, size, vec![id.clone()]);
        Some(id)
    }

    fn labels_for(&self, address: u32, size: usize) -> Vec<String> {
        let Some(end) = address.checked_add(size as u32) else {
            return Vec::new();
        };
        let mut labels = BTreeSet::new();
        for range in &self.ranges {
            if address < range.end && end > range.start {
                labels.extend(range.labels.iter().cloned());
                if labels.len() >= MAX_LABELS_PER_RANGE {
                    break;
                }
            }
        }
        labels.into_iter().take(MAX_LABELS_PER_RANGE).collect()
    }

    fn replace_range(&mut self, address: u32, size: usize, mut labels: Vec<String>) {
        let Some(end) = address.checked_add(size as u32) else {
            self.truncated = true;
            return;
        };
        if size == 0 {
            return;
        }
        labels.sort();
        labels.dedup();
        labels.truncate(MAX_LABELS_PER_RANGE);
        let mut next = Vec::with_capacity(self.ranges.len().saturating_add(1));
        for range in self.ranges.drain(..) {
            if address >= range.end || end <= range.start {
                next.push(range);
                continue;
            }
            if range.start < address {
                next.push(TaintRange {
                    start: range.start,
                    end: address,
                    labels: range.labels.clone(),
                });
            }
            if range.end > end {
                next.push(TaintRange {
                    start: end,
                    end: range.end,
                    labels: range.labels,
                });
            }
        }
        if !labels.is_empty() {
            next.push(TaintRange {
                start: address,
                end,
                labels,
            });
        }
        next.sort_by_key(|range| range.start);
        let mut merged: Vec<TaintRange> = Vec::with_capacity(next.len());
        for range in next {
            if let Some(previous) = merged.last_mut()
                && previous.end == range.start
                && previous.labels == range.labels
            {
                previous.end = range.end;
            } else {
                merged.push(range);
            }
        }
        if merged.len() > MAX_RANGES {
            merged.truncate(MAX_RANGES);
            self.truncated = true;
        }
        self.ranges = merged;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propagates_and_overwrites_bounded_labels() {
        let mut tracker = ProvenanceTracker::default();
        tracker.source(
            ProvenanceSourceKind::Network,
            "response",
            0x1000,
            16,
            "InternetReadFile",
            1,
        );
        tracker.propagate(0x1000, 0x2000, 8);
        tracker.observe(
            0x2000,
            8,
            ProvenanceSinkKind::ProcessCommand,
            "cmd",
            "WinExec",
            2,
        );
        tracker.clear(0x2000, 8);
        tracker.observe(
            0x2000,
            8,
            ProvenanceSinkKind::NetworkRequest,
            "sink",
            "send",
            3,
        );
        let (sources, flows, stats) = tracker.finish();
        assert_eq!(sources.len(), 1);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].source_ids, vec!["source-0001"]);
        assert_eq!(stats.flow_count, 1);
    }

    #[test]
    fn records_transformation_parents() {
        let mut tracker = ProvenanceTracker::default();
        tracker.source(
            ProvenanceSourceKind::Registry,
            "value",
            0x1000,
            8,
            "RegQueryValueExA",
            1,
        );
        tracker.derive(0x1000, 0x2000, 8, "decoded", "decoder", 2);
        let (sources, _, _) = tracker.finish();
        assert_eq!(sources[1].parent_ids, vec!["source-0001"]);
    }
}
