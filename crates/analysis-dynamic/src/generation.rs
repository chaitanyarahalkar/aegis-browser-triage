use crate::{GenerationStats, PayloadGeneration};
use std::collections::BTreeMap;

pub const MAX_GENERATIONS: usize = 256;

#[derive(Debug, Default)]
pub struct GenerationTracker {
    generations: Vec<PayloadGeneration>,
    current_by_region: BTreeMap<u32, usize>,
    truncated: bool,
}

pub struct GenerationObservation<'a> {
    pub artifact_id: String,
    pub region_base: u32,
    pub size: u64,
    pub instruction: u64,
    pub virtual_time_ms: u64,
    pub trigger: &'a str,
    pub permissions: String,
    pub executed: bool,
    pub entry_point_overwrite: bool,
    pub executable_heap: bool,
}

impl GenerationTracker {
    pub fn observe(&mut self, observation: GenerationObservation<'_>) {
        if let Some(index) = self
            .current_by_region
            .get(&observation.region_base)
            .copied()
            && self.generations[index].artifact_id == observation.artifact_id
        {
            let generation = &mut self.generations[index];
            generation.executed |= observation.executed;
            generation.entry_point_overwrite |= observation.entry_point_overwrite;
            generation.executable_heap |= observation.executable_heap;
            return;
        }
        if self.generations.len() >= MAX_GENERATIONS {
            self.truncated = true;
            return;
        }
        let parent_id = self
            .current_by_region
            .get(&observation.region_base)
            .map(|index| self.generations[*index].id.clone());
        let sequence = self.generations.len() as u64;
        let id = format!(
            "generation-{sequence:04}-{}",
            &observation.artifact_id[..12]
        );
        self.generations.push(PayloadGeneration {
            id,
            sequence,
            parent_id,
            artifact_id: observation.artifact_id,
            region_base: observation.region_base.into(),
            size: observation.size,
            capture_instruction: observation.instruction,
            virtual_time_ms: observation.virtual_time_ms,
            trigger: observation.trigger.into(),
            permissions: observation.permissions,
            executed: observation.executed,
            entry_point_overwrite: observation.entry_point_overwrite,
            executable_heap: observation.executable_heap,
        });
        self.current_by_region
            .insert(observation.region_base, self.generations.len() - 1);
    }

    pub fn finish(self) -> (Vec<PayloadGeneration>, GenerationStats) {
        let chains = self
            .generations
            .iter()
            .filter(|generation| generation.parent_id.is_none())
            .count();
        let executed_generations = self
            .generations
            .iter()
            .filter(|generation| generation.executed)
            .count();
        let stats = GenerationStats {
            count: self.generations.len(),
            chains,
            executed_generations,
            truncated: self.truncated,
        };
        (self.generations, stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(id: &str, executed: bool) -> GenerationObservation<'_> {
        GenerationObservation {
            artifact_id: id.into(),
            region_base: 0x1000,
            size: 4096,
            instruction: 10,
            virtual_time_ms: 20,
            trigger: "test",
            permissions: "r-x".into(),
            executed,
            entry_point_overwrite: false,
            executable_heap: true,
        }
    }

    #[test]
    fn links_distinct_region_versions_and_merges_repeated_observations() {
        let mut tracker = GenerationTracker::default();
        tracker.observe(observation(&"a".repeat(64), false));
        tracker.observe(observation(&"a".repeat(64), true));
        tracker.observe(observation(&"b".repeat(64), true));
        let (generations, stats) = tracker.finish();
        assert_eq!(generations.len(), 2);
        assert!(generations[0].executed);
        assert_eq!(
            generations[1].parent_id.as_deref(),
            Some(generations[0].id.as_str())
        );
        assert_eq!(stats.chains, 1);
    }
}
