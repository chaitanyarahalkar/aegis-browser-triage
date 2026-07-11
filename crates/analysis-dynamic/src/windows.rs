use std::collections::BTreeMap;

const MAX_HANDLES: usize = 4_096;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum HandleResource {
    File { path: String, offset: usize },
    Module { name: String },
    Registry { key: String },
    Internet { label: String },
    Process { pid: u32 },
    Thread { tid: u32 },
}

#[derive(Debug)]
pub struct VirtualWindows {
    next_handle: u32,
    handles: BTreeMap<u32, HandleResource>,
    last_error: u32,
    files: BTreeMap<String, Vec<u8>>,
    total_file_bytes: usize,
    registry: BTreeMap<String, Vec<u8>>,
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
            None => None,
        }
    }

    pub fn last_error(&self) -> u32 {
        self.last_error
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
