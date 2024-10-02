# VirusTotal Intelligence Dork - Files

## Introduction

VirusTotal Intelligence (VTI) allows one to search through VirusTotal's entire dataset accordingly to many different variables, from binary properties, antivirus detection verdicts, behaviour patterns such as outgoing communication, and more. 
VTI provides powerful search capabilities. This README will focus on the File corpus (entity:file)

All search terms is structured as ***modifier:value***.

## Hunting Behaviours

Files hosted on a .gov with at least 5 detections
```
itw:"*.gov" p:5+
```

Files communicating with IP address
```
behaviour:"8.8.8.8"
```

Files communicating with microsoft.com (alternative method that's more precise)
```
behaviour_network:"microsoft.com"
```

Suspicious powershell useage <br>
_(note that VT doesn't have parent-child links in the search modifiers. It could very well be a separate process in the search below, though rare)_
```
behaviour_files:"-enc" OR behaviour_files:"FromBase64String"

(behaviour_command_executions:powershell.exe AND (behaviour_created_processes:rundll32.exe OR behaviour_created_processes:powershell.exe))
```

Suspicious LOLbins
```
behaviour_processes:"certutil -urlcache -split -f http"

behaviour_processes:"mshta *.hta"

behaviour_created_processes: 
```

Hunting for RDP misuse <br>
_(enabling RDP, disabling NLA)_
```
behaviour_command_executions:"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0"

behaviour_registry:"HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication"
```

Files that run specific processes <br>
_(this example hunts for known ransomware behaviours - deleting shadow copies)_
```
behaviour_processes:"\\vssadmin.exe delete shadows /all /quiet"

behaviour_processes:"\\vssadmin.exe resize shadowstorage"

behaviour_command_executions:"Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}" NOT engines:ransome
```