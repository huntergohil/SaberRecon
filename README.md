# SaberRecon
<p align="center">
  <a href="https://sabershield.net">
    <img src="static/SaberShieldLogoWithTextWithBackground.png" alt="Sabershield Cybersecurity" width="400">
  </a>
</p>

SaberRecon is a cybersecurity reconnaissance tool developed by the owner and founder of Sabershield Cybersecurity LLC, Hunter Gohil. The goal of this project is to simplify the initial phase of reconnaissance for penetration testers, bug bounty hunters, and cybersecurity professionals. 

# Disclaimer 
SaberRecon is intended **only for use against systems you own or have been explicitly authorized to test**.  
Unauthorized scanning, probing, or reconnaissance may violate local, state, federal, or international laws.

**SaberShield Cybersecurity LLC assumes no responsibility or liability** for misuse of this tool or for actions taken by users.  
By using SaberRecon, you acknowledge that you are solely responsible for ensuring all activities are legal, ethical, and properly authorized.
# Installation 
Installing SaberRecon is simple! Run these two commands: 
```bash
docker pull huntergohil/saberrecon:latest
```
```bash
docker run -d --name saberrecon -p 8080:8080 huntergohil/saberrecon:latest
```
Of course, you can replace port 8080 with any port you desire. 
You can now navigate to 127.0.0.1:8080 and begin utilizing the tool. 

# Utilization 
Simply enter any link that you wish to begin reconnaissance on. 

The following reconnaissance tools will all be used against the target: 
WhoIs, NSLookup, DIGDNS, Nmap (Fast Scan), CURL, WhatWeb Fingerprint, subfinder, GoBuster, and WAFWoof 

Please be patient as these tools run, as they may take 1-2 minutes. Upon completion, the UI will automatically navigate to the report. 
From the report page, you can view each tool's result and search by tool. 

You can also visit the history page to view previous tests. You can also download these results as HTML documents from the history page. 

TOOLS SECTION: 
Navigating to tools allows users to view each tool individually and customize the flags which are ran against the target. 

Some flags may require elevated privileges, and the developers are currently investigating the best solution for these flags to maximize security for the user. 


#Future Plans 
There are two primary future plans for SaberRecon: 
1. Integrate AI usage 
There will be the option to provide an AI API key and utilize openAI to analyze reports. This will allow users to quickly and easily identify potential vulnerabilities and recieve guidance on the next steps they should take to discover the vulnerability. 

2. Multiple tool selection 
There will be an option for users to individually select tools and flags to use and combine them into a single report. This will allow for more readable reports that can be more useful for analysis. 
