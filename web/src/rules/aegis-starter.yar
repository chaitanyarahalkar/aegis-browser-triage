rule Aegis_Safe_Demo : demo safe {
  meta:
    description = "Identifies the first-party Aegis safe test fixture"
    severity = "info"
    author = "Aegis"
  strings:
    $marker = "powershell.exe -NoProfile https://example.test 10.20.30.40" ascii
  condition:
    $marker
}

rule Suspicious_PowerShell_Download : script network {
  meta:
    description = "PowerShell download primitives appear together"
    severity = "medium"
    author = "Aegis"
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
    author = "Aegis"
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
    author = "Aegis"
  strings:
    $upx0 = "UPX0" ascii
    $upx1 = "UPX1" ascii
  condition:
    all of them
}
