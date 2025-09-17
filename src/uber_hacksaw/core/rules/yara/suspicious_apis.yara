rule Suspicious_Win32_APIs
{
  meta:
    description = "Detects suspicious Win32 API usage patterns"
    author = "uber-hacksaw"
    severity = "high"
    confidence = "medium"
  strings:
    $create_process = "CreateProcess" nocase
    $virtual_alloc = "VirtualAlloc" nocase
    $write_process = "WriteProcessMemory" nocase
    $reg_open = "RegOpenKey" nocase
    $internet_open = "InternetOpen" nocase
  condition:
    3 of them
}