use crate::DynamicError;

#[derive(Debug, Clone, Copy)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Permissions {
    pub const READ: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };

    pub fn display(self) -> String {
        format!(
            "{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' }
        )
    }
}

#[derive(Debug)]
struct Region {
    start: u32,
    data: Vec<u8>,
    permissions: Permissions,
    name: String,
    dirty: bool,
    write_ranges: Vec<(u32, u32)>,
}

impl Region {
    fn end(&self) -> u32 {
        self.start.saturating_add(self.data.len() as u32)
    }

    fn contains(&self, address: u32, length: usize) -> bool {
        let Some(end) = address.checked_add(length as u32) else {
            return false;
        };
        address >= self.start && end <= self.end()
    }
}

#[derive(Debug, Default)]
pub struct Memory {
    regions: Vec<Region>,
    allocated: usize,
}

impl Memory {
    pub fn map(
        &mut self,
        start: u32,
        size: usize,
        permissions: Permissions,
        name: impl Into<String>,
    ) -> Result<(), DynamicError> {
        if size == 0 || self.allocated.saturating_add(size) > crate::HARD_MAX_MEMORY_BYTES {
            return Err(DynamicError::MemoryLimit);
        }
        let end = start
            .checked_add(size as u32)
            .ok_or(DynamicError::MemoryLimit)?;
        if self
            .regions
            .iter()
            .any(|region| start < region.end() && end > region.start)
        {
            return Err(DynamicError::OverlappingRegion { address: start });
        }
        self.allocated += size;
        self.regions.push(Region {
            start,
            data: vec![0; size],
            permissions,
            name: name.into(),
            dirty: false,
            write_ranges: Vec::new(),
        });
        self.regions.sort_by_key(|region| region.start);
        Ok(())
    }

    pub fn read(&self, address: u32, length: usize) -> Result<&[u8], DynamicError> {
        let region = self
            .regions
            .iter()
            .find(|region| region.contains(address, length) && region.permissions.read)
            .ok_or(DynamicError::MemoryRead { address })?;
        let offset = (address - region.start) as usize;
        Ok(&region.data[offset..offset + length])
    }

    pub fn fetch(&self, address: u32, max_length: usize) -> Result<&[u8], DynamicError> {
        let region = self
            .regions
            .iter()
            .find(|region| {
                address >= region.start && address < region.end() && region.permissions.execute
            })
            .ok_or(DynamicError::MemoryExecute { address })?;
        let offset = (address - region.start) as usize;
        let end = (offset + max_length).min(region.data.len());
        Ok(&region.data[offset..end])
    }

    pub fn write(&mut self, address: u32, data: &[u8]) -> Result<(), DynamicError> {
        self.write_inner(address, data, false)
    }

    pub fn write_force(&mut self, address: u32, data: &[u8]) -> Result<(), DynamicError> {
        self.write_inner(address, data, true)
    }

    fn write_inner(&mut self, address: u32, data: &[u8], force: bool) -> Result<(), DynamicError> {
        let region = self
            .regions
            .iter_mut()
            .find(|region| {
                region.contains(address, data.len()) && (force || region.permissions.write)
            })
            .ok_or(DynamicError::MemoryWrite { address })?;
        let offset = (address - region.start) as usize;
        region.data[offset..offset + data.len()].copy_from_slice(data);
        if !force && !data.is_empty() {
            region.dirty = true;
            let end = address.saturating_add(data.len() as u32);
            if let Some((last_start, last_end)) = region.write_ranges.last_mut()
                && address <= *last_end
            {
                *last_start = (*last_start).min(address);
                *last_end = (*last_end).max(end);
            } else if region.write_ranges.len() < 256 {
                region.write_ranges.push((address, end));
            }
        }
        Ok(())
    }

    pub fn read_u8(&self, address: u32) -> Result<u8, DynamicError> {
        Ok(self.read(address, 1)?[0])
    }

    pub fn read_u16(&self, address: u32) -> Result<u16, DynamicError> {
        Ok(u16::from_le_bytes(
            self.read(address, 2)?.try_into().unwrap(),
        ))
    }

    pub fn read_u32(&self, address: u32) -> Result<u32, DynamicError> {
        Ok(u32::from_le_bytes(
            self.read(address, 4)?.try_into().unwrap(),
        ))
    }

    pub fn write_u8(&mut self, address: u32, value: u8) -> Result<(), DynamicError> {
        self.write(address, &[value])
    }

    pub fn write_u16(&mut self, address: u32, value: u16) -> Result<(), DynamicError> {
        self.write(address, &value.to_le_bytes())
    }

    pub fn write_u32(&mut self, address: u32, value: u32) -> Result<(), DynamicError> {
        self.write(address, &value.to_le_bytes())
    }

    pub fn read_c_string(&self, address: u32, max: usize) -> String {
        let mut result = Vec::new();
        for index in 0..max {
            match self.read_u8(address.wrapping_add(index as u32)) {
                Ok(0) | Err(_) => break,
                Ok(byte) => result.push(byte),
            }
        }
        String::from_utf8_lossy(&result).into_owned()
    }

    pub fn read_wide_string(&self, address: u32, max: usize) -> String {
        let mut result = Vec::new();
        for index in 0..max {
            match self.read_u16(address.wrapping_add((index * 2) as u32)) {
                Ok(0) | Err(_) => break,
                Ok(value) => result.push(value),
            }
        }
        String::from_utf16_lossy(&result)
    }

    pub fn set_permissions(
        &mut self,
        address: u32,
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

    pub fn unmap(&mut self, address: u32) -> bool {
        let Some(index) = self
            .regions
            .iter()
            .position(|region| region.start == address)
        else {
            return false;
        };
        let region = self.regions.remove(index);
        self.allocated = self.allocated.saturating_sub(region.data.len());
        true
    }

    pub fn snapshot(&self, address: u32) -> Option<MemoryRegionView<'_>> {
        self.regions
            .iter()
            .find(|region| address >= region.start && address < region.end())
            .map(|region| MemoryRegionView {
                start: region.start,
                name: &region.name,
                permissions: region.permissions,
                dirty: region.dirty,
                data: &region.data,
            })
    }

    pub fn was_written(&self, address: u32) -> bool {
        self.regions.iter().any(|region| {
            region
                .write_ranges
                .iter()
                .any(|(start, end)| address >= *start && address < *end)
        })
    }

    pub fn dirty_regions(&self) -> impl Iterator<Item = MemoryRegionView<'_>> {
        self.regions
            .iter()
            .filter(|region| region.dirty)
            .map(|region| MemoryRegionView {
                start: region.start,
                name: &region.name,
                permissions: region.permissions,
                dirty: true,
                data: &region.data,
            })
    }
}

#[derive(Clone, Copy)]
pub struct MemoryRegionView<'a> {
    pub start: u32,
    pub name: &'a str,
    pub permissions: Permissions,
    pub dirty: bool,
    pub data: &'a [u8],
}
