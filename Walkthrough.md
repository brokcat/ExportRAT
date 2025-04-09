🧠 ExportRAT - Lab Walkthrough

📁 Initial Sample  
**File Name**: export.rar  
**MD5**: c700d75303b8cc2ea8a996cd5e975ec1  
**Source**: MalwareBazaar Sample Link

---

### 🧩 Q1 – What is the name of the main executable file contained in export.rar?

🔍 **Investigation**  
Search the MD5 hash `c700d75303b8cc2ea8a996cd5e975ec1` on [MalwareBazaar](https://bazaar.abuse.ch).  
In the **Contained Files** section, identify the file with a MIME type indicating it's a Windows executable (`application/x-dosexec`).

✅ **Answer**  
x334761.dat  
(Note: Despite the `.dat` extension, this file is a disguised PE executable)

---

### 🧩 Q2 – What malware family name is assigned to the sample according to Hybrid Analysis?

🔍 **Investigation**  
Search the SHA256 hash `8cc57bc1284f68b2aae1e6cb8fa86793db131e9bbbfb40b5eb235a0628c57da9` on [Hybrid Analysis](https://hybrid-analysis.com).  
Check the **AV detection section** or **Overview tab** for the label or family name assigned to the sample.

✅ **Answer**  
ZephyrMiner

---

### 🧩 Q3 – Which IP address is contacted by the payload after execution?

🔍 **Investigation**  
Use the SHA256 hash to search on Hybrid Analysis.  
Go to the Network section > Contacted Hosts or DNS requests.  
Note any suspicious IP address contacted by the sample.

✅ **Answer**  
185.234.247.118

---

### 🧩 Q4 – What country is this IP located in?

🔍 **Investigation**  
Go to AbuseIPDB or IPinfo.io.  
Paste the IP and check the geolocation info.

✅ **Answer**  
Russia

---

### 🧩 Q5 – What domain name does the payload use to contact its C2 server?

🔍 **Investigation**  
In Hybrid Analysis, check HTTP requests or DNS requests.  
If not visible, check the Behavior tab or use ANY.RUN.

✅ **Answer**  
morningglow[.]ddns[.]net

---

### 🧩 Q6 – What is the name of the executable dropped to disk after extraction?

🔍 **Investigation**  
In Hybrid Analysis, navigate to the Dropped Files tab.  
Look for .exe or .dll files written to AppData, Temp, or Startup.

✅ **Answer**  
x334761.dat  
(Note: Even though .dat, this file is a disguised PE executable)

---

### 🧩 Q7 – Which Windows registry key is modified to achieve persistence?

🔍 **Investigation**  
Go to the Registry Activity tab in Hybrid Analysis or ANY.RUN.  
Look for keys under CurrentVersion\Run.

✅ **Answer**  
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OfficeUpdate

---

### 🧩 Q8 – Which protocol does the malware use to communicate with its C2?

🔍 **Investigation**  
Check Network tab in Hybrid Analysis or packet capture data.  
Observe the protocol used to reach the C2 (HTTP, HTTPS, DNS tunneling, etc.).

✅ **Answer**  
HTTP

---

### 🧾 Summary of IOCs

| Type        | Value                                                        |
|-------------|--------------------------------------------------------------|
| MD5         | c700d75303b8cc2ea8a996cd5e975ec1                             |
| SHA256      | 8cc57bc1284f68b2aae1e6cb8fa86793db131e9bbbfb40b5eb235a0628c57da9 |
| IP          | 185.234.247.118                                              |
| Domain      | morningglow.ddns.net                                         |
| Dropped File| x334761.dat                                                  |
| Registry    | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OfficeUpdate |
| Protocol    | HTTP                                                         |

---

### 🔧 Tools Used

- VirusTotal  
- MalwareBazaar  
- Hybrid Analysis  
- ANY.RUN  
- AbuseIPDB  
- IPinfo.io

---

### 🏁 Conclusion

This lab demonstrates how to perform an in-depth analysis of a real-world Remote Access Trojan using OSINT tools. By tracing its artifacts across multiple platforms, you’ve uncovered its infrastructure, persistence techniques, and potential attribution.

Stay sharp, analyst. 🕵️‍♂️
