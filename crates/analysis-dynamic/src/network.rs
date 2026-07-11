use crate::{HttpScenario, NetworkHeader, NetworkScenario};
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct NetworkRuntime {
    scenario: NetworkScenario,
    handles: BTreeMap<u32, NetworkHandle>,
}

#[derive(Debug)]
enum NetworkHandle {
    Session,
    Connection {
        host: String,
        port: u16,
    },
    Request {
        method: String,
        url: String,
        request_headers: Vec<NetworkHeader>,
        request_body: Vec<u8>,
        response: Vec<u8>,
        cursor: usize,
        status: u16,
        response_headers: Vec<NetworkHeader>,
    },
    Socket {
        destination: Option<String>,
        response: Vec<u8>,
        cursor: usize,
    },
}

#[derive(Clone)]
pub struct ResolvedHttp {
    pub url: String,
    pub status: u16,
    pub headers: Vec<NetworkHeader>,
    pub body: Vec<u8>,
    pub redirected: bool,
}

impl NetworkRuntime {
    pub fn new(scenario: NetworkScenario) -> Self {
        Self {
            scenario,
            handles: BTreeMap::new(),
        }
    }
    pub fn scenario_id(&self) -> &str {
        &self.scenario.id
    }
    pub fn register_session(&mut self, handle: u32) {
        self.handles.insert(handle, NetworkHandle::Session);
    }
    pub fn register_connection(&mut self, handle: u32, host: String, port: u16) {
        self.handles
            .insert(handle, NetworkHandle::Connection { host, port });
    }
    pub fn register_socket(&mut self, handle: u32) {
        self.handles.insert(
            handle,
            NetworkHandle::Socket {
                destination: None,
                response: Vec::new(),
                cursor: 0,
            },
        );
    }
    pub fn connection_url(&self, handle: u32, path: &str) -> Option<String> {
        match self.handles.get(&handle) {
            Some(NetworkHandle::Connection { host, port }) => Some(format!(
                "http://{host}{}{path}",
                if *port == 80 {
                    String::new()
                } else {
                    format!(":{port}")
                }
            )),
            _ => None,
        }
    }
    pub fn register_request(&mut self, handle: u32, method: String, url: String) {
        self.handles.insert(
            handle,
            NetworkHandle::Request {
                method,
                url,
                request_headers: Vec::new(),
                request_body: Vec::new(),
                response: Vec::new(),
                cursor: 0,
                status: 0,
                response_headers: Vec::new(),
            },
        );
    }
    pub fn set_request(&mut self, handle: u32, headers: Vec<NetworkHeader>, body: Vec<u8>) {
        if let Some(NetworkHandle::Request {
            request_headers,
            request_body,
            ..
        }) = self.handles.get_mut(&handle)
        {
            *request_headers = headers;
            *request_body = body;
        }
    }
    pub fn request_metadata(
        &self,
        handle: u32,
    ) -> Option<(String, String, Vec<NetworkHeader>, Vec<u8>)> {
        match self.handles.get(&handle) {
            Some(NetworkHandle::Request {
                method,
                url,
                request_headers,
                request_body,
                ..
            }) => Some((
                method.clone(),
                url.clone(),
                request_headers.clone(),
                request_body.clone(),
            )),
            _ => None,
        }
    }
    pub fn resolve_request(&mut self, handle: u32) -> Vec<ResolvedHttp> {
        let Some(NetworkHandle::Request {
            url,
            response,
            cursor,
            status,
            response_headers,
            ..
        }) = self.handles.get_mut(&handle)
        else {
            return Vec::new();
        };
        let mut current = url.clone();
        let mut hops = Vec::new();
        for depth in 0..=3 {
            let route = self
                .scenario
                .http
                .iter()
                .find(|route| route.url.eq_ignore_ascii_case(&current))
                .cloned()
                .unwrap_or_else(|| HttpScenario {
                    url: current.clone(),
                    status: 404,
                    headers: Vec::new(),
                    body: Vec::new(),
                    redirect_to: None,
                });
            let redirected = route.redirect_to.is_some() && depth < 3;
            hops.push(ResolvedHttp {
                url: current.clone(),
                status: route.status,
                headers: route.headers.clone(),
                body: route.body.clone(),
                redirected,
            });
            if let Some(next) = route.redirect_to.filter(|_| depth < 3) {
                current = next;
            } else {
                *url = current;
                *response = route.body;
                *cursor = 0;
                *status = route.status;
                *response_headers = route.headers;
                break;
            }
        }
        hops
    }
    pub fn read_response(&mut self, handle: u32, maximum: usize) -> Option<Vec<u8>> {
        let NetworkHandle::Request {
            response, cursor, ..
        } = self.handles.get_mut(&handle)?
        else {
            return None;
        };
        let end = cursor.saturating_add(maximum).min(response.len());
        let bytes = response.get(*cursor..end)?.to_vec();
        *cursor = end;
        Some(bytes)
    }
    pub fn response_status(&self, handle: u32) -> Option<u16> {
        match self.handles.get(&handle) {
            Some(NetworkHandle::Request { status, .. }) => Some(*status),
            _ => None,
        }
    }
    pub fn resolve_dns(&self, host: &str) -> Option<[u8; 4]> {
        self.scenario
            .dns
            .iter()
            .find(|item| item.host.eq_ignore_ascii_case(host))
            .map(|item| item.address)
    }
    pub fn connect_socket(&mut self, handle: u32, destination: String) {
        let scripted = self
            .scenario
            .sockets
            .iter()
            .find(|item| item.destination == destination)
            .map(|item| item.response.clone())
            .unwrap_or_default();
        if let Some(NetworkHandle::Socket {
            destination: target,
            response,
            cursor,
        }) = self.handles.get_mut(&handle)
        {
            *target = Some(destination);
            *response = scripted;
            *cursor = 0;
        }
    }
    pub fn socket_destination(&self, handle: u32) -> Option<String> {
        match self.handles.get(&handle) {
            Some(NetworkHandle::Socket { destination, .. }) => destination.clone(),
            _ => None,
        }
    }
    pub fn recv_socket(&mut self, handle: u32, maximum: usize) -> Option<Vec<u8>> {
        let NetworkHandle::Socket {
            response, cursor, ..
        } = self.handles.get_mut(&handle)?
        else {
            return None;
        };
        let end = cursor.saturating_add(maximum).min(response.len());
        let bytes = response.get(*cursor..end)?.to_vec();
        *cursor = end;
        Some(bytes)
    }
    pub fn close(&mut self, handle: u32) {
        self.handles.remove(&handle);
    }
}
