# SaberRecon
<p align="center">
  <a href="https://sabershield.net">
    <img src="static/SaberShieldLogoWithTextWithBackground.png" alt="Sabershield Cybersecurity" width="400">
  </a>
</p>

SaberRecon is a cybersecurity reconnaissance tool developed by the owner and founder of Sabershield Cybersecurity LLC, Hunter Gohil. The goal of this project is to simplify the initial phase of reconnaissance for penetration testers, bug bounty hunters, and cybersecurity professionals. 

# Disclaimer 
SaberRecon is a tool that is designed to be used ONLY with the permission of the target. Any actions taken by any users with this tool are NOT the responsibility of Sabershield Cybersecurity LLC. 

# Installation 
Installating SaberRecon is simple! Run these two commands: 

docker pull huntergohil/saberrecon:latest

docker run -d --name saberrecon -p 8080:8080 huntergohil/saberrecon:latest

Of course, you can replace port 8080 with any port you desire. 
You can now navigate to 127.0.0.1:8080 and begin utilizing the tool. 

# Utilization 
Simply enter any link that you wish to begin reconnaissance on. 

The following reconnaissance tools will all be used against the target: 
WhoIs, NSLookup, DIGDNS, Nmap (Fast Scan), CURL, WhatWeb Fingerprint, subfinder, GoBuster, and WAFWoof 

Please be patient as these tools run, as they may take 1-2 minutes. Upon completion, the UI will automatically navigate to the report. 
From the report page, you can view each tool's result and search by tool. 

You can also visit the history page to view previous tests. You can also download these results as HTML documents from the history page. 
