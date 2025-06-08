# 🧠 Memory Forensics - Slow Computer Investigation (Windows 10)

## 🧾 Summary

This memory analysis was performed on a Windows 10 system that was experiencing unexpected slowness and instability. Using Volatility 3, I performed triage to check for signs of malware, persistence mechanisms, or abnormal memory usage patterns.

## 🔧 Tools Used

- Volatility 3
- Plugins: `pslist`, `cmdline`, `malfind`, `dlllist`, `netscan`
- YARA (basic ruleset)
- Strings, CyberChef, VirusTotal

## 📊 Key Findings

| Evidence | Plugin | Description |
|----------|--------|-------------|
| Long-running `rundll32.exe` with no command line | pslist / cmdline | Suspicious process |
| Unknown injected memory region | malfind | High entropy shellcode |
| Unusual DLL with no signature | dlllist | Possible malware component |

## 📂 Included Files

- `summary.txt`: Analyst notes
- `volatility-commands.txt`: Full plugin chain
- `screenshots/`: Output screenshots

## 🎯 MITRE ATT&CK Mapping

- T1055 – Process Injection
- T1059 – Scripting Execution
- T1027 – Obfuscated Files or Information

## 🧠 Lessons Learned

- Even “slow performance” cases can reveal hidden malware
- Memory-based analysis is powerful for uncovering LOLBins and injection
- Behavioral TTP mapping is more useful than just IOC hunting
