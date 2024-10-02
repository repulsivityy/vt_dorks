# VirusTotal Intelligence Dork (vt-dork)

## Introduction

VirusTotal Intelligence (VTI) allows one to search through VirusTotal's entire dataset accordingly to many different variables, from binary properties, antivirus detection verdicts, behaviour patterns such as outgoing communication, and more. 
VTI provides powerful search capabilities with mulitple search modiferes to search across the different data corpus of Files, Domains, IP Address, URLs. <br>

All search terms is structured as ***modifier:value***.
The image below from VirusTotal's blog provides the basis of how information is structured. 

<p align="center">
  <img src="https://lh7-rt.googleusercontent.com/docsz/AD_4nXdJ1cLcETZLA8AQG4szbnYyDQdEk3zn9PTtfcf7pwun5Kf-pAhYxQPH5Rf02WL8rxGBklRa7uyCo04VctDMuGTeku6k_yLvna6MiDfpsyuUEveCg50ppeUzElUz4ZWSLR6l6p6uvrzRVR3aezkSAiDDNFU?key=fmyi2KLpW11xkeIveMXX7Q" width="800" alt="VirusTotal Dataset Structure"> <br>
<a href="https://blog.virustotal.com/2024/08/VT-S1-EffectiveResearch.html">Exploring the VirusTotal Dataset</a>
</p>

This document will list searches that are relevant for threat hunting on VT.  
Separate files will focus on the different VT Corpus set.  

README_FILE.MD = files, 
README_DOMAINS_URLS.MD for domains and URLs,
README_IP = IP Address


## General Searches

Searching for files with at least 10 detections
```
entity:file p:10+
```

Searching for files with at least 10 detections that have been detected as a malware (in this case, ransomware) <br>
_modifier engines is use for malware family names, malware types (eg, info-stealers, trojans, etc), or malware categories_
```
entity:file p:10+ engines:ransom
```

Searching for any filenames starting the string _mimi_ <br>
_(the "entity:file" modifer is not required as the modifier "name" implies searching through the File corpus, but is included for clarity and consistency sake)_

```
entity:file name:mimi* 
```

Searching for pe files submitted to VT with 20 detections, submitted in Singapore
```
entity:file type:pe p:20+ submitter:sg
```

Searching for excel files between 1-5 detections that have macros
```
entity:file type:excel p:1+ p:5- tag:macros
```

Searching for files weaponised that exploits any vulnerability in 2024 last seen in the past 14 days
```
tag:cve-2024-* ls:14d+ 
```

Showing all lummac samples last seen in the past 7 days
```
engines:lummac ls:7d+
```

Searching for all sliver samples last analysed in the past 14 days
```
engines:sliver la:14d+
```

Searching for trojans observed in Taiwan, with > 10 submissions, and >10 unique sources
```
engines:trojan AND submitter:tw AND submissions:10+ AND sources:10+
```

## Hunting with Content Searches 

Files with specific strings: 
```
content:"UploadSmallFileWithStopWatch"
```

Content / Binary Seaches
```
content:"{ 46 69 6C 65 43 6F 6E 74 61 69 6E 65 72 2E 46 69 6C 65 41 72 63 68 69 76 65 }"
```



