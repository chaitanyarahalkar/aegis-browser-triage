#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    Stdcall,
    Cdecl,
}

#[derive(Debug, Clone, Copy)]
pub struct ApiSignature {
    pub argument_count: usize,
    pub convention: CallingConvention,
    pub modeled: bool,
}

pub fn normalize_name(name: &str) -> String {
    let trimmed = name.trim_start_matches('_');
    let undecorated = trimmed
        .rsplit_once('@')
        .filter(|(_, suffix)| suffix.chars().all(|character| character.is_ascii_digit()))
        .map_or(trimmed, |(base, _)| base);
    undecorated.to_ascii_lowercase()
}

pub fn signature(name: &str) -> ApiSignature {
    let normalized = normalize_name(name);
    let (argument_count, modeled) = match normalized.as_str() {
        "gettickcount"
        | "getcurrentprocessid"
        | "getcurrentthreadid"
        | "getprocessheap"
        | "getcommandlinea"
        | "getcommandlinew"
        | "getlasterror" => (0, true),
        "exitprocess"
        | "sleep"
        | "getmodulehandlea"
        | "getmodulehandlew"
        | "loadlibrarya"
        | "loadlibraryw"
        | "deletefilea"
        | "deletefilew"
        | "closehandle"
        | "regclosekey"
        | "internetclosehandle"
        | "localfree"
        | "globalfree"
        | "heapdestroy"
        | "setlasterror" => (1, true),
        "winexec"
        | "getprocaddress"
        | "virtualfree"
        | "localalloc"
        | "globalalloc"
        | "checkremotedebuggerpresent" => (2, true),
        "virtualprotect"
        | "connect"
        | "heapfree"
        | "getenvironmentvariablea"
        | "getenvironmentvariablew" => (3, true),
        "virtualalloc" | "send" | "recv" => (4, true),
        "heapalloc" => (3, true),
        "regopenkeyexa" | "regopenkeyexw" | "internetopena" | "internetopenw" | "writefile"
        | "readfile" => (5, true),
        "regsetvalueexa" | "regsetvalueexw" | "internetopenurla" | "internetopenurlw" => (6, true),
        "createfilea" | "createfilew" => (7, true),
        "createprocessa" | "createprocessw" => (10, true),
        "openprocess" | "queueuserapc" => (3, true),
        "virtualallocex"
        | "writeprocessmemory"
        | "virtualprotectex"
        | "ntqueryinformationprocess" => (5, true),
        "createremotethread" => (7, true),
        "resumethread" => (1, true),
        "isdebuggerpresent" => (0, true),
        "queryperformancecounter" | "getsysteminfo" | "globalmemorystatusex" => (1, true),
        "getcomputernamea"
        | "getcomputernamew"
        | "getusernamea"
        | "getusernamew"
        | "gettemppatha"
        | "gettemppathw"
        | "getwindowsdirectorya"
        | "getwindowsdirectoryw"
        | "getsystemdirectorya"
        | "getsystemdirectoryw" => (2, true),
        "gettempfilenamea" | "gettempfilenamew" => (4, true),
        "wsastartup" => (2, true),
        "socket" => (3, true),
        "closesocket" | "gethostbyname" | "freeaddrinfo" => (1, true),
        "getaddrinfo" => (4, true),
        "regcreatekeyexa" | "regcreatekeyexw" => (9, true),
        "regqueryvalueexa" | "regqueryvalueexw" => (6, true),
        "regdeletevaluea" | "regdeletevaluew" | "regdeletekeya" | "regdeletekeyw" => (2, true),
        _ => (decorated_argument_count(name).unwrap_or(0), false),
    };
    ApiSignature {
        argument_count,
        convention: if normalized.starts_with("wsprintf") {
            CallingConvention::Cdecl
        } else {
            CallingConvention::Stdcall
        },
        modeled,
    }
}

fn decorated_argument_count(name: &str) -> Option<usize> {
    let (_, bytes) = name.rsplit_once('@')?;
    bytes.parse::<usize>().ok().map(|bytes| bytes / 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_and_decorated_signatures() {
        assert_eq!(signature("CreateFileW").argument_count, 7);
        assert!(signature("_CreateFileW@28").modeled);
        assert_eq!(signature("_UnknownApi@16").argument_count, 4);
        assert!(!signature("_UnknownApi@16").modeled);
        assert_eq!(signature("CreateRemoteThread").argument_count, 7);
        assert_eq!(signature("CreateProcessW").argument_count, 10);
    }
}
