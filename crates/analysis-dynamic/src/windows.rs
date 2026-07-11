use std::collections::BTreeMap;

const MAX_HANDLES: usize = 4_096;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REMOTE_REGION_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOTAL_REMOTE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum HandleResource {
    File {
        path: String,
        offset: usize,
    },
    Module {
        name: String,
    },
    Registry {
        key: String,
    },
    Internet {
        label: String,
    },
    Process {
        pid: u32,
    },
    Thread {
        tid: u32,
    },
    Heap {
        label: String,
    },
    Service {
        name: String,
    },
    Mutex {
        name: String,
        owned: bool,
    },
    Event {
        name: String,
        signaled: bool,
        manual_reset: bool,
    },
    Mapping {
        name: String,
        size: usize,
    },
    Token {
        pid: u32,
    },
    Snapshot {
        index: usize,
    },
    Find {
        entries: Vec<String>,
        index: usize,
    },
    CryptoProvider,
    CryptoHash {
        data: Vec<u8>,
    },
}

#[derive(Debug)]
pub struct VirtualWindows {
    next_handle: u32,
    handles: BTreeMap<u32, HandleResource>,
    last_error: u32,
    files: BTreeMap<String, Vec<u8>>,
    total_file_bytes: usize,
    registry: BTreeMap<String, Vec<u8>>,
    remote_memory: BTreeMap<(u32, u32), Vec<u8>>,
    total_remote_bytes: usize,
}

impl Default for VirtualWindows {
    fn default() -> Self {
        Self {
            next_handle: 0x100,
            handles: BTreeMap::new(),
            last_error: 0,
            files: BTreeMap::new(),
            total_file_bytes: 0,
            registry: BTreeMap::new(),
            remote_memory: BTreeMap::new(),
            total_remote_bytes: 0,
        }
    }
}

impl VirtualWindows {
    pub fn allocate(&mut self, resource: HandleResource) -> Option<u32> {
        if self.handles.len() >= MAX_HANDLES {
            self.last_error = 4;
            return None;
        }
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1);
        self.handles.insert(handle, resource);
        Some(handle)
    }

    pub fn close(&mut self, handle: u32) -> bool {
        let closed = self.handles.remove(&handle).is_some();
        self.last_error = if closed { 0 } else { 6 };
        closed
    }

    pub fn file_path(&self, handle: u32) -> Option<&str> {
        match self.handles.get(&handle) {
            Some(HandleResource::File { path, .. }) => Some(path),
            _ => None,
        }
    }

    pub fn module_name(&self, handle: u32) -> Option<&str> {
        match self.handles.get(&handle) {
            Some(HandleResource::Module { name }) => Some(name),
            _ => None,
        }
    }

    pub fn describe(&self, handle: u32) -> Option<String> {
        match self.handles.get(&handle) {
            Some(HandleResource::File { path, .. }) => Some(path.clone()),
            Some(HandleResource::Module { name }) => Some(name.clone()),
            Some(HandleResource::Registry { key }) => Some(key.clone()),
            Some(HandleResource::Internet { label }) => Some(label.clone()),
            Some(HandleResource::Process { pid }) => Some(format!("process:{pid}")),
            Some(HandleResource::Thread { tid }) => Some(format!("thread:{tid}")),
            Some(HandleResource::Heap { label }) => Some(label.clone()),
            Some(HandleResource::Service { name }) => Some(name.clone()),
            Some(HandleResource::Mutex { name, .. }) => Some(format!("mutex:{name}")),
            Some(HandleResource::Event { name, .. }) => Some(format!("event:{name}")),
            Some(HandleResource::Mapping { name, .. }) => Some(format!("mapping:{name}")),
            Some(HandleResource::Token { pid }) => Some(format!("token:{pid}")),
            Some(HandleResource::Snapshot { .. }) => Some("process snapshot".into()),
            Some(HandleResource::Find { .. }) => Some("file enumeration".into()),
            Some(HandleResource::CryptoProvider) => Some("crypto provider".into()),
            Some(HandleResource::CryptoHash { .. }) => Some("crypto hash".into()),
            None => None,
        }
    }

    pub fn last_error(&self) -> u32 {
        self.last_error
    }

    pub fn signal_event(&mut self, handle: u32, signaled: bool) -> bool {
        match self.handles.get_mut(&handle) {
            Some(HandleResource::Event {
                signaled: value, ..
            }) => {
                *value = signaled;
                true
            }
            _ => false,
        }
    }

    pub fn release_mutex(&mut self, handle: u32) -> bool {
        match self.handles.get_mut(&handle) {
            Some(HandleResource::Mutex { owned, .. }) => {
                *owned = false;
                true
            }
            _ => false,
        }
    }

    pub fn wait(&mut self, handle: u32) -> Option<bool> {
        match self.handles.get_mut(&handle) {
            Some(HandleResource::Event {
                signaled,
                manual_reset,
                ..
            }) => {
                let ready = *signaled;
                if ready && !*manual_reset {
                    *signaled = false;
                }
                Some(ready)
            }
            Some(HandleResource::Mutex { owned, .. }) => {
                let ready = !*owned;
                if ready {
                    *owned = true;
                }
                Some(ready)
            }
            Some(HandleResource::Thread { .. }) | Some(HandleResource::Process { .. }) => {
                Some(true)
            }
            _ => None,
        }
    }

    pub fn mapping_size(&self, handle: u32) -> Option<usize> {
        match self.handles.get(&handle) {
            Some(HandleResource::Mapping { size, .. }) => Some(*size),
            _ => None,
        }
    }

    pub fn start_file_find(&mut self, pattern: &str) -> Option<(u32, String)> {
        let needle = pattern.trim_matches('*').to_ascii_lowercase();
        let entries: Vec<_> = self
            .files
            .keys()
            .filter(|path| needle.is_empty() || path.to_ascii_lowercase().contains(&needle))
            .cloned()
            .collect();
        let first = entries.first()?.clone();
        let handle = self.allocate(HandleResource::Find { entries, index: 1 })?;
        Some((handle, first))
    }

    pub fn next_file_find(&mut self, handle: u32) -> Option<String> {
        let HandleResource::Find { entries, index } = self.handles.get_mut(&handle)? else {
            return None;
        };
        let value = entries.get(*index)?.clone();
        *index += 1;
        Some(value)
    }

    pub fn next_process(&mut self, handle: u32, reset: bool) -> Option<(u32, &'static str)> {
        const PROCESSES: &[(u32, &str)] =
            &[(4, "System"), (1200, "explorer.exe"), (1337, "sample.exe")];
        let HandleResource::Snapshot { index } = self.handles.get_mut(&handle)? else {
            return None;
        };
        if reset {
            *index = 0;
        }
        let value = PROCESSES.get(*index).copied()?;
        *index += 1;
        Some(value)
    }

    pub fn hash_update(&mut self, handle: u32, bytes: &[u8]) -> bool {
        match self.handles.get_mut(&handle) {
            Some(HandleResource::CryptoHash { data })
                if data.len().saturating_add(bytes.len()) <= 4 * 1024 * 1024 =>
            {
                data.extend_from_slice(bytes);
                true
            }
            _ => false,
        }
    }

    pub fn hash_bytes(&self, handle: u32) -> Option<&[u8]> {
        match self.handles.get(&handle) {
            Some(HandleResource::CryptoHash { data }) => Some(data),
            _ => None,
        }
    }

    pub fn set_last_error(&mut self, value: u32) {
        self.last_error = value;
    }

    pub fn open_file(&mut self, path: String) -> Option<u32> {
        self.files.entry(path.clone()).or_default();
        self.allocate(HandleResource::File { path, offset: 0 })
    }

    pub fn write_file(&mut self, handle: u32, data: &[u8]) -> usize {
        let Some(HandleResource::File { path, offset }) = self.handles.get_mut(&handle) else {
            self.last_error = 6;
            return 0;
        };
        let file = self.files.entry(path.clone()).or_default();
        let available_file = MAX_FILE_BYTES.saturating_sub(*offset);
        let available_total = MAX_TOTAL_FILE_BYTES.saturating_sub(self.total_file_bytes);
        let length = data.len().min(available_file).min(available_total);
        if *offset > file.len() {
            file.resize(*offset, 0);
        }
        let end = offset.saturating_add(length);
        let previous_length = file.len();
        if end > file.len() {
            file.resize(end, 0);
        }
        file[*offset..end].copy_from_slice(&data[..length]);
        *offset = end;
        self.total_file_bytes = self
            .total_file_bytes
            .saturating_add(file.len().saturating_sub(previous_length));
        self.last_error = if length == data.len() { 0 } else { 8 };
        length
    }

    pub fn read_file(&mut self, handle: u32, requested: usize) -> Vec<u8> {
        let Some(HandleResource::File { path, offset }) = self.handles.get_mut(&handle) else {
            self.last_error = 6;
            return Vec::new();
        };
        let Some(file) = self.files.get(path) else {
            return Vec::new();
        };
        let end = offset.saturating_add(requested).min(file.len());
        let result = file.get(*offset..end).unwrap_or_default().to_vec();
        *offset = end;
        self.last_error = 0;
        result
    }

    pub fn file_size(&self, handle: u32) -> Option<usize> {
        let path = self.file_path(handle)?;
        self.files.get(path).map(Vec::len)
    }

    pub fn set_file_offset(&mut self, handle: u32, distance: i32, method: u32) -> Option<usize> {
        let (path, current) = match self.handles.get(&handle) {
            Some(HandleResource::File { path, offset }) => (path.clone(), *offset),
            _ => return None,
        };
        let base = match method {
            0 => 0i64,
            1 => current as i64,
            2 => self.files.get(&path).map_or(0, Vec::len) as i64,
            _ => return None,
        };
        let next = base.saturating_add(distance as i64).max(0) as usize;
        if let Some(HandleResource::File { offset, .. }) = self.handles.get_mut(&handle) {
            *offset = next.min(MAX_FILE_BYTES);
        }
        Some(next.min(MAX_FILE_BYTES))
    }

    pub fn delete_file(&mut self, path: &str) -> bool {
        let Some(data) = self.files.remove(path) else {
            return false;
        };
        self.total_file_bytes = self.total_file_bytes.saturating_sub(data.len());
        true
    }

    pub fn copy_file(&mut self, source: &str, destination: &str) -> bool {
        let Some(data) = self.files.get(source).cloned() else {
            return false;
        };
        let current = self.files.get(destination).map_or(0, Vec::len);
        if self
            .total_file_bytes
            .saturating_add(data.len().saturating_sub(current))
            > MAX_TOTAL_FILE_BYTES
        {
            self.last_error = 8;
            return false;
        }
        let previous = self
            .files
            .insert(destination.into(), data.clone())
            .map_or(0, |value| value.len());
        self.total_file_bytes = self
            .total_file_bytes
            .saturating_sub(previous)
            .saturating_add(data.len());
        true
    }

    pub fn move_file(&mut self, source: &str, destination: &str) -> bool {
        let Some(data) = self.files.remove(source) else {
            return false;
        };
        if let Some(previous) = self.files.insert(destination.into(), data) {
            self.total_file_bytes = self.total_file_bytes.saturating_sub(previous.len());
        }
        for resource in self.handles.values_mut() {
            if let HandleResource::File { path, .. } = resource
                && path == source
            {
                *path = destination.into();
            }
        }
        true
    }

    pub fn registry_path(&self, handle: u32) -> Option<&str> {
        match self.handles.get(&handle) {
            Some(HandleResource::Registry { key }) => Some(key),
            _ => None,
        }
    }

    pub fn set_registry_value(&mut self, handle: u32, name: &str, data: &[u8]) -> bool {
        let Some(key) = self.registry_path(handle) else {
            self.last_error = 6;
            return false;
        };
        self.registry
            .insert(format!("{key}\\{name}"), data.to_vec());
        self.last_error = 0;
        true
    }

    pub fn registry_value(&self, handle: u32, name: &str) -> Option<&[u8]> {
        let key = self.registry_path(handle)?;
        self.registry
            .get(&format!("{key}\\{name}"))
            .map(Vec::as_slice)
    }

    pub fn delete_registry_value(&mut self, handle: u32, name: &str) -> bool {
        let Some(key) = self.registry_path(handle) else {
            self.last_error = 6;
            return false;
        };
        let removed = self.registry.remove(&format!("{key}\\{name}")).is_some();
        self.last_error = if removed { 0 } else { 2 };
        removed
    }

    pub fn open_process(&mut self, pid: u32) -> Option<u32> {
        self.allocate(HandleResource::Process { pid })
    }

    pub fn allocate_remote(&mut self, process: u32, address: u32, size: usize) -> bool {
        if !matches!(
            self.handles.get(&process),
            Some(HandleResource::Process { .. })
        ) || size == 0
            || size > MAX_REMOTE_REGION_BYTES
            || self.total_remote_bytes.saturating_add(size) > MAX_TOTAL_REMOTE_BYTES
        {
            self.last_error = 8;
            return false;
        }
        if self.remote_memory.keys().any(|(handle, start)| {
            *handle == process
                && address
                    < start.saturating_add(self.remote_memory[&(*handle, *start)].len() as u32)
                && address.saturating_add(size as u32) > *start
        }) {
            self.last_error = 487;
            return false;
        }
        self.remote_memory.insert((process, address), vec![0; size]);
        self.total_remote_bytes = self.total_remote_bytes.saturating_add(size);
        self.last_error = 0;
        true
    }

    pub fn write_remote(&mut self, process: u32, address: u32, data: &[u8]) -> usize {
        let Some(((.., start), region)) =
            self.remote_memory
                .iter_mut()
                .find(|((handle, start), region)| {
                    *handle == process
                        && address >= *start
                        && address.saturating_add(data.len() as u32)
                            <= start.saturating_add(region.len() as u32)
                })
        else {
            self.last_error = 299;
            return 0;
        };
        let offset = address.saturating_sub(*start) as usize;
        region[offset..offset + data.len()].copy_from_slice(data);
        self.last_error = 0;
        data.len()
    }

    pub fn file_snapshots(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.files
            .iter()
            .filter(|(_, bytes)| !bytes.is_empty())
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
    }

    pub fn remote_snapshots(&self) -> impl Iterator<Item = (u32, u32, &[u8])> {
        self.remote_memory
            .iter()
            .filter(|(_, bytes)| bytes.iter().any(|byte| *byte != 0))
            .map(|((process, address), bytes)| (*process, *address, bytes.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_files_preserve_content_across_handles() {
        let mut windows = VirtualWindows::default();
        let writer = windows.open_file("C:\\Temp\\sample.bin".into()).unwrap();
        assert_eq!(windows.write_file(writer, b"aegis"), 5);
        let reader = windows.open_file("C:\\Temp\\sample.bin".into()).unwrap();
        assert_eq!(windows.read_file(reader, 3), b"aeg");
        assert_eq!(windows.read_file(reader, 8), b"is");
        assert!(windows.close(writer));
        assert!(windows.close(reader));
    }
}
