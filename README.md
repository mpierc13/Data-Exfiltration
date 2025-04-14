## **Data Exfiltration from PIP'd Employee** 
![image](https://github.com/user-attachments/assets/bc5a0402-3a09-4e86-a438-5d47120f6bc6)



# **Use Case**   

## **Scenario:**  
An employee named John Doe, working in a sensitive department, was recently placed on a performance improvement plan (PIP). After displaying concerning behavior, management suspects John may be planning to steal proprietary information and leave the company. The investigation involves analyzing activities on John’s corporate device (`marcels-vm`) using Microsoft Defender for Endpoint (MDE).  

---

## **Incident Summary and Findings**  

### **Timeline Overview**  
1. **Archiving Activity:**  
   - **Observed Behavior:** Frequent creation of `.zip` files in a folder labeled "backup."  
   - **Detection Query (KQL):**  
     ```kql
     DeviceFileEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceNetworkEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceProcessEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceFileEvents
     | where DeviceName == "marcels-vm"
     | where FileName endswith ".zip"
     | order by Timestamp desc
     ```
![image](https://github.com/user-attachments/assets/862212b7-30a9-4c5c-8673-f4c9a11e5970)


     
2. **Process Analysis:**  
   - **Observed Behavior:** I took one of the instances of a zip file being created, took the timestamp and searched under DeviceProcessEvents for anything happening 2 minutes before the archive was created and 2 mintutes after. I discoverd around the same time, a PowerShell script silently installed 7zip and then used 7zip to zip up employee data into an archive.
   - **Detection Query (KQL):**  

     ```kql
     let VMName = "marcels-vm";
     let specificTime = datetime(2025-04-08T14:25:18.1958941Z);
     DeviceProcessEvents
     | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
     | where DeviceName == VMName
     | order by Timestamp desc
     | project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
     ```
![image](https://github.com/user-attachments/assets/1929e4a2-60d4-46d0-8e7f-dde305d99380)



   3. **Network Exfiltration Check:**  
   - **Observed Behavior:** No evidence of data exfiltration via network logs during the time frame.  

   - **Detection Query (KQL):**  

     ```kql
     let VMName = "marcels-vm";
     let specificTime = datetime(2025-04-08T14:25:18.1958941Z);
     DeviceProcessEvents
     | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
     | where DeviceName == VMName
     | order by Timestamp desc
     ```  

4. **Response:**  
   - Shared findings with the manager, highlighting automated archive creation and no immediate signs of exfiltration. The device was isolated, awaiting further instructions.

---

---

## **MITRE ATT&CK Framework TTPs**  

| **Technique**                                                                                      | **ID**        | **Description**                                                                                                                                                     |
|----------------------------------------------------------------------------------------------------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)   | T1059.001     | PowerShell was used to silently install 7-Zip and create ZIP archives, suggesting malicious script-based execution.                                                |
| [Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)     | T1560.001     | The use of 7-Zip to compress data supports this technique, where data is archived before exfiltration.                                                             |
| [Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004/)        | T1070.004     | Archiving and backing up files could be an attempt to obscure or stage data for exfiltration while avoiding detection.                                             |
| [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)                               | T1105         | Silent installation of 7-Zip indicates a tool was transferred to the system, aligning with this technique.                                                         |
| [Process Injection: Extra Window Memory Injection](https://attack.mitre.org/techniques/T1055/011/)| T1055.011     | Though not confirmed, PowerShell-based silent actions often involve process injection to execute payloads stealthily.                                               |
| [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)                     | T1027         | Silent installation and use of scripts may involve obfuscation to bypass security tools.                                                                            |
| [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)                  | T1047         | While not explicitly observed, silent script execution may leverage WMI for local or remote process automation.                                                     |
                                                     
---

### **Next Steps**  
1. Monitor John’s account activity for unusual access or privilege escalation.  
2. Implement DLP (Data Loss Prevention) measures to alert on potential data exfiltration.  
3. Escalate findings to management and recommend a follow-up review of John's device for additional forensic artifacts.  

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Created By:
- **Author Name**: Marcel Pierce
- **Author Contact**: https://www.linkedin.com/in/marcel-pierce-1a49b52a5/
- **Date**: Apr 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---
