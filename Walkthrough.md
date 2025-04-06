# 🧠 ExportRAT - Lab Walkthrough

## 📁 Initial Sample

**File Name**: `export.rar`  
**MD5**: `c700d75303b8cc2ea8a996cd5e975ec1`  
**Source**: [MalwareBazaar Sample Link](https://bazaar.abuse.ch/sample/41922718d01c427b27799385fddcac0fa5666373afa3c893623aa900cb9911a0/)

---

## 🧩 Q1 – What is the family name of the malware embedded in `export.rar`?

### 🔍 Investigation
1. Upload or search the MD5 hash on [VirusTotal](https://www.virustotal.com).
2. Alternatively, search it on [MalwareBazaar](https://bazaar.abuse.ch).
3. From the tags or threat labels, you will often find the malware family.

### ✅ Answer
**Remcos**  
The sample was tagged as a **Remote Access Trojan (RAT)**, specifically **Remcos**.

---

## 🧩 Q2 – What is the SHA256 hash of the extracted payload inside `export.rar`?

### 🔍 Investigation
1. On MalwareBazaar, check the section **Contained Files**.
2. One of the embedded files (extracted from the `.rar`) is an executable with a `.dat` or `.exe` extension.
3. The SHA256 is listed next to it.

### ✅ Answer
**41922718d01c427b27799385fddcac0fa5666373afa3c893623aa900cb9911a0**

---

## 🧩 Q3 – Which IP address is contacted by the payload after execution?

### 🔍 Investigation
1. Use the SHA256 hash to search on [Hybrid Analysis](https://www.hybrid-analysis.com).
2. Go to the **Network** section > **Contacted Hosts** or **DNS requests**.
3. Note any suspicious IP address contacted by the sample.

### ✅ Answer
**185.234.247.118**

---

## 🧩 Q4 – What country is this IP located in?

### 🔍 Investigation
1. Go to [AbuseIPDB](https://abuseipdb.com) or [IPinfo.io](https://ipinfo.io/185.234.247.118).
2. Paste the IP and check the geolocation info.

### ✅ Answer
**Russia**

---

## 🧩 Q5 – What domain name does the payload use to contact its C2 server?

### 🔍 Investigation
1. In Hybrid Analysis, check **HTTP requests** or **DNS requests**.
2. If not visible, check the **Behavior** tab or use ANY.RUN.

### ✅ Answer
**morningglow[.]ddns[.]net**

---

## 🧩 Q6 – What is the name of the executable dropped to disk after extraction?

### 🔍 Investigation
1. In Hybrid Analysis, navigate to the **Dropped Files** tab.
2. Look for `.exe` or `.dll` files written to `AppData`, `Temp`, or `Startup`.

### ✅ Answer
**x334761.dat**

(*Note: Even though `.dat`, this file is a disguised PE executable*)

---

## 🧩 Q7 – Which Windows registry key is modified to achieve persistence?

### 🔍 Investigation
1. Go to the **Registry Activity** tab in Hybrid Analysis or ANY.RUN.
2. Look for keys under `CurrentVersion\Run`.

### ✅ Answer
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OfficeUpdate`

---

## 🧩 Q8 – Which protocol does the malware use to communicate with its C2?

### 🔍 Investigation
1. Check **Network** tab in Hybrid Analysis or packet capture data.
2. Observe the protocol used to reach the C2 (HTTP, HTTPS, DNS tunneling, etc.).

### ✅ Answer
**HTTP**

---

## 🧾 Summary of IOCs

| Type       | Value                                   |
|------------|-----------------------------------------|
| MD5        | c700d75303b8cc2ea8a996cd5e975ec1         |
| SHA256     | 41922718d01c427b27799385fddcac0fa5666373afa3c893623aa900cb9911a0 |
| IP         | 185.234.247.118                         |
| Domain     | morningglow.ddns.net                    |
| Dropped File | x334761.dat                           |
| Registry   | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OfficeUpdate |
| Protocol   | HTTP                                    |

---

## 🔧 Tools Used

- [VirusTotal](https://www.virustotal.com)
- [MalwareBazaar](https://bazaar.abuse.ch)
- [Hybrid Analysis](https://www.hybrid-analysis.com)
- [ANY.RUN](https://any.run)
- [AbuseIPDB](https://abuseipdb.com)
- [IPinfo.io](https://ipinfo.io)

---

## 🏁 Conclusion

This lab demonstrates how to perform an in-depth analysis of a real-world Remote Access Trojan (Remcos) using OSINT tools. By tracing its artifacts across multiple platforms, you’ve uncovered its infrastructure, persistence techniques, and potential attribution.

Stay sharp, analyst. 🕵️‍♂️
