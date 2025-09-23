param([string]$Path = "C:\Cases\beacon.ps1")
$code  = Get-Content $Path -Raw
$bytes = [System.Text.Encoding]::Unicode.GetBytes($code)  # UTF-16LE
$enc   = [Convert]::ToBase64String($bytes)
"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -enc $enc"
