rule NOPE_Safe_Demo : demo safe {
  meta:
    description = "Identifies the first-party NOPE safe test fixture"
    severity = "info"
    author = "NOPE"
  strings:
    $marker = "powershell.exe -NoProfile https://example.test 10.20.30.40" ascii
  condition:
    $marker
}

rule Suspicious_PowerShell_Download : script network {
  meta:
    description = "PowerShell download primitives appear together"
    severity = "medium"
    author = "NOPE"
  strings:
    $powershell = "powershell" ascii wide nocase
    $download_1 = "DownloadString" ascii wide nocase
    $download_2 = "Invoke-WebRequest" ascii wide nocase
  condition:
    $powershell and any of ($download_*)
}

rule Suspicious_Process_Injection_APIs : injection windows {
  meta:
    description = "Common process-injection APIs appear together"
    severity = "high"
    author = "NOPE"
  strings:
    $open = "OpenProcess" ascii wide
    $write = "WriteProcessMemory" ascii wide
    $thread = "CreateRemoteThread" ascii wide
  condition:
    2 of them
}

rule Suspicious_UPX_Markers : packer {
  meta:
    description = "Multiple UPX section markers are present"
    severity = "low"
    author = "NOPE"
  strings:
    $upx0 = "UPX0" ascii
    $upx1 = "UPX1" ascii
  condition:
    all of them
}

rule NOPE_Safe_Runtime_Artifact : demo safe runtime {
  meta:
    description = "Identifies the first-party inert runtime artifact fixture"
    severity = "info"
    author = "NOPE"
  strings:
    $marker = "AEGIS_SAFE_RUNTIME_ARTIFACT" ascii
  condition:
    $marker
}

rule NOPE_Safe_Network_Download : demo safe network {
  meta:
    description = "Identifies the first-party inert scripted network download"
    severity = "info"
    author = "NOPE"
  strings:
    $marker = "AEGIS_SAFE_NETWORK_DOWNLOAD" ascii
  condition:
    $marker
}

rule NOPE_Safe_Linux_Artifact : demo safe linux runtime {
  meta:
    description = "Identifies the first-party inert Linux runtime artifact fixture"
    severity = "info"
    author = "NOPE"
  strings:
    $marker = "NOPE_SAFE_LINUX_ARTIFACT" ascii
  condition:
    $marker
}
