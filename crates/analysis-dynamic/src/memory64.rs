use crate::{DynamicError, memory::Permissions};

pub(crate) const MAX_EXACT_GUEST_ADDRESS: u64 = (1u64 << 53) - 1;

#[derive(Debug)]
struct Region64 {
    start: u64,
    data: Vec<u8>,
    permissions: Permissions,
    name: String,
    dirty: bool,
    written_ranges: Vec<(u64, u64)>,
}

impl Region64 {
    fn end(&self) -> u64 {
        self.start.saturating_add(self.data.len() as u64)
    }

    fn contains(&self, address: u64, length: usize) -> bool {
        address
            .checked_add(length as u64)
            .is_some_and(|end| address >= self.start && end <= self.end())
    }
}

#[derive(Debug, Default)]
pub(crate) struct Memory64 {
    regions: Vec<Region64>,
    allocated: usize,
}

impl Memory64 {
    pub fn map(
        &mut self,
        start: u64,
        size: usize,
        permissions: Permissions,
        name: impl Into<String>,
    ) -> Result<(), DynamicError> {
        if size == 0 || self.allocated.saturating_add(size) > crate::HARD_MAX_MEMORY_BYTES {
            return Err(DynamicError::MemoryLimit);
        }
        let end = start
            .checked_add(size as u64)
            .ok_or(DynamicError::MemoryLimit)?;
        if end > MAX_EXACT_GUEST_ADDRESS {
            return Err(DynamicError::MemoryLimit);
        }
        if self
            .regions
            .iter()
            .any(|region| start < region.end() && end > region.start)
        {
            return Err(DynamicError::OverlappingRegion { address: start });
        }
        self.allocated += size;
        self.regions.push(Region64 {
            start,
            data: vec![0; size],
            permissions,
            name: name.into(),
            dirty: false,
            written_ranges: Vec::new(),
        });
        self.regions.sort_by_key(|region| region.start);
        Ok(())
    }

    pub fn read(&self, address: u64, length: usize) -> Result<&[u8], DynamicError> {
        let region = self
            .regions
            .iter()
            .find(|region| region.contains(address, length) && region.permissions.read)
            .ok_or(DynamicError::MemoryRead { address })?;
        let offset = (address - region.start) as usize;
        Ok(&region.data[offset..offset + length])
    }

    pub fn fetch(&self, address: u64, maximum: usize) -> Result<&[u8], DynamicError> {
        let region = self
            .regions
            .iter()
            .find(|region| {
                address >= region.start && address < region.end() && region.permissions.execute
            })
            .ok_or(DynamicError::MemoryExecute { address })?;
        let offset = (address - region.start) as usize;
        Ok(&region.data[offset..(offset + maximum).min(region.data.len())])
    }

    pub fn write(&mut self, address: u64, data: &[u8]) -> Result<(), DynamicError> {
        self.write_inner(address, data, false)
    }

    pub fn write_force(&mut self, address: u64, data: &[u8]) -> Result<(), DynamicError> {
        self.write_inner(address, data, true)
    }

    fn write_inner(&mut self, address: u64, data: &[u8], force: bool) -> Result<(), DynamicError> {
        let region = self
            .regions
            .iter_mut()
            .find(|region| {
                region.contains(address, data.len()) && (force || region.permissions.write)
            })
            .ok_or(DynamicError::MemoryWrite { address })?;
        let offset = (address - region.start) as usize;
        region.data[offset..offset + data.len()].copy_from_slice(data);
        region.dirty |= !force && !data.is_empty();
        if !force && !data.is_empty() {
            let end = address.saturating_add(data.len() as u64);
            let mut start = address;
            let mut finish = end;
            region.written_ranges.retain(|(range_start, range_end)| {
                if start <= *range_end && finish >= *range_start {
                    start = start.min(*range_start);
                    finish = finish.max(*range_end);
                    false
                } else {
                    true
                }
            });
            if region.written_ranges.len() < 4_096 {
                region.written_ranges.push((start, finish));
                region.written_ranges.sort_unstable_by_key(|range| range.0);
            }
        }
        Ok(())
    }

    pub fn read_u64(&self, address: u64) -> Result<u64, DynamicError> {
        Ok(u64::from_le_bytes(
            self.read(address, 8)?.try_into().unwrap(),
        ))
    }

    pub fn read_u16(&self, address: u64) -> Result<u16, DynamicError> {
        Ok(u16::from_le_bytes(
            self.read(address, 2)?.try_into().unwrap(),
        ))
    }

    pub fn write_u64(&mut self, address: u64, value: u64) -> Result<(), DynamicError> {
        self.write(address, &value.to_le_bytes())
    }

    pub fn write_u32(&mut self, address: u64, value: u32) -> Result<(), DynamicError> {
        self.write(address, &value.to_le_bytes())
    }

    pub fn read_c_string(&self, address: u64, maximum: usize) -> String {
        let mut bytes = Vec::new();
        for offset in 0..maximum {
            match self.read(address.saturating_add(offset as u64), 1) {
                Ok([0]) | Err(_) => break,
                Ok(value) => bytes.push(value[0]),
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    pub fn read_wide_string(&self, address: u64, maximum: usize) -> String {
        let mut units = Vec::new();
        for offset in 0..maximum {
            let pointer = address.saturating_add((offset * 2) as u64);
            let Ok(unit) = self.read_u16(pointer) else {
                break;
            };
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        String::from_utf16_lossy(&units)
    }

    pub fn set_permissions(
        &mut self,
        address: u64,
        size: usize,
        permissions: Permissions,
    ) -> Result<(), DynamicError> {
        let region = self
            .regions
            .iter_mut()
            .find(|region| region.contains(address, size))
            .ok_or(DynamicError::MemoryWrite { address })?;
        region.permissions = permissions;
        Ok(())
    }

    pub fn dirty_regions(&self) -> impl Iterator<Item = Memory64RegionView<'_>> {
        self.regions
            .iter()
            .filter(|region| region.dirty)
            .map(|region| Memory64RegionView {
                start: region.start,
                data: &region.data,
                permissions: region.permissions,
                name: &region.name,
            })
    }

    pub fn was_written(&self, address: u64) -> bool {
        self.regions.iter().any(|region| {
            region
                .written_ranges
                .iter()
                .any(|(start, end)| address >= *start && address < *end)
        })
    }
}

pub(crate) struct Memory64RegionView<'a> {
    pub start: u64,
    pub data: &'a [u8],
    pub permissions: Permissions,
    pub name: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_sparse_regions_above_four_gibibytes() {
        let mut memory = Memory64::default();
        let address = 0x0000_0001_4000_0000;
        memory
            .map(address, 0x1000, Permissions::READ_WRITE, "PE64 image")
            .unwrap();
        memory
            .write_u64(address + 0x100, 0x1122_3344_5566_7788)
            .unwrap();
        assert_eq!(
            memory.read_u64(address + 0x100).unwrap(),
            0x1122_3344_5566_7788
        );
        assert!(memory.was_written(address + 0x100));
        assert!(!memory.was_written(address + 0x108));
        assert!(matches!(
            memory.map(address + 0x800, 0x1000, Permissions::READ, "overlap"),
            Err(DynamicError::OverlappingRegion { .. })
        ));
        assert!(matches!(
            memory.map(
                MAX_EXACT_GUEST_ADDRESS,
                0x1000,
                Permissions::READ,
                "unsafe JSON address"
            ),
            Err(DynamicError::MemoryLimit)
        ));
    }

    #[test]
    fn reads_bounded_utf16_strings_from_sparse_guest_memory() {
        let mut memory = Memory64::default();
        let address = 0x0000_0001_5000_0000;
        memory
            .map(address, 0x1000, Permissions::READ_WRITE, "wide string")
            .unwrap();
        let bytes: Vec<u8> = "KERNEL32.dll\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        memory.write(address, &bytes).unwrap();
        assert_eq!(memory.read_wide_string(address, 260), "KERNEL32.dll");
        assert_eq!(memory.read_wide_string(address, 6), "KERNEL");
    }
}
