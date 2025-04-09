🧠 APT38 – Hermes Sample Walkthrough (drmaiprave.exe)
📁 Initial Sample
File Name: drmaiprave.exe

MD5: 77c29d464efcae961424ae050453ef11

Source: VirusTotal Report

Context: Identified as a variant of Hermes ransomware, linked to APT38 (Lazarus Group), used during financially motivated cyber operations.

✅ Step-by-Step Solution
🧩 Q1 – What is the name of the analyzed file?
Answer: drmaiprave.exe
🔎 Found in VirusTotal's file details.

🧩 Q2 – What is the file type?
Answer: PE32 executable (Windows)
🔎 Confirmed by file metadata and static analysis.

🧩 Q3 – Which APT group is linked to this sample?
Answer: APT38 (Lazarus)
🔎 Attribution based on reports from Mandiant, MITRE, and others.

🧩 Q4 – What MITRE ATT&CK TTP is used for persistence?
Answer: T1547.001 – Registry Run Key
🔎 The malware modifies HKCU\Software\Microsoft\Windows\CurrentVersion\Run to maintain persistence.

🧩 Q5 – What TTP is used for execution?
Answer: T1059.003 – Windows Command Shell
🔎 Executes commands via cmd.exe as part of its runtime behavior.

🧩 Q6 – What evasion technique is used?
Answer: T1027 – Obfuscated Files or Information
🔎 Uses packing and obfuscation to avoid static detection.

🧩 Q7 – What protocol is used for C2 communication?
Answer: HTTP(S)
🔎 Observed network traffic indicates outbound HTTP/S requests to C2 servers.

🧩 Q8 – What is the primary function of the malware?
Answer: Ransomware (Hermes)
🔎 Encrypts system files and drops a ransom note.

🧩 Q9 – Does the malware serve a secondary role? If yes, what is it?
Answer: Diversion post-breach (covering tracks after fraud)
🔎 Hermes is used post-operation to destroy evidence and distract incident responders.

🧩 Q10 – What MITRE ID corresponds to the final observed tactic?
Answer: T1486 – Data Encrypted for Impact
🔎 Final action involves encrypting data for disruption.
