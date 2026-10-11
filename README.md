# Elk-and-Cybersec

The Windows Command Processor, cmd.exe, is a critical system tool. It is used to interpret commands entered by the user and then carry out the appropriate actions. In addition, it provides a scripting language that can be used to automate tasks. Because of its importance, it is essential to monitor cmd.exe usage. There are a number of reasons why monitoring cmd.exe usage is important. First, because of its power, cmd.exe can be used to perform harmful actions on a system. Second, because it is a scripting language, malicious users can use it to create scripts that perform unwanted or harmful actions 


**Exercises to be done:**
1. Create a Kibana Dashboard to show the number of times powershell.exe was run as a process
2. Create a Kibana Dashboard to show the number of times powershell.exe was run as a process 	Novice
3. Create a Kibana Dashboard to show the number of times an Administrator has logged in 	Novice
4. Write an ELK filter to detect user logons 	Novice
5. Write a simple search query using the ELK User Interface Novice
6. Create a Kibana Dashboard to show the number of times cmd.exe is run as a process 	Novice
7. Write a simple search query using the Elastic Query Language 	Novice
8. Write ELK filters that detects simple attacks

Working with elastic search commands:
1. sudo systemctl status elsaticsearch (status/start/kill.enable)


Sometimes a  problem: the agent is still using an invalid API key. The Windows integration is fine, Sysmon is fine, but nothing can reach Elasticsearch until authentication works.


**Task 2 — Verify Mimikatz execution
Step 1: Check Sysmon on the Windows VM**
Open PowerShell as Administrator and run:

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} -MaxEvents 200 |
Where-Object {
    $_.Message -match 'mimikatz\.exe'
} |
Select-Object TimeCreated, Message |
Format-List


**Create a Kibana Dashboard to show the number of times powershell.exe was run as a process**
In this exercise, we configured a Windows system to collect PowerShell process activity using Sysmon and Elastic Agent and visualize the collected events in Kibana. We created a dynamic dashboard with a line graph showing PowerShell usage over time, a bar graph showing PowerShell activity by host, and a bar graph showing PowerShell executions with administrator privileges. The dashboard can be viewed across different time ranges, including the last hour, 24 hours, and seven days. The purpose of the exercise was to demonstrate how security telemetry can be visualized and used to monitor PowerShell activity for future threat-hunting investigations.

**ELK**  is the acronym for three open source projects: Elasticsearch, Logstash, and Kibana. lasticsearch is a search and analytics engine. Logstash is a server-side data processing pipeline that ingests data from multiple sources simultaneously, transforms it, and then sends it to a "stash" like Elasticsearch. Kibana lets users visualize data with charts and graphs in Elasticsearch.

A security analyst uses ELK SIEM to detect and prevent cyberattacks. ELK SIEM allows the security analyst to collect and analyze data from a variety of sources, including network traffic, firewalls, and endpoint devices. The security analyst can use this data to identify patterns that may indicate a cyberattack. ELK SIEM also helps the analyst to track and respond to incidents quickly and effectively. 

