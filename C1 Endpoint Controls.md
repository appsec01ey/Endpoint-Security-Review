### Endpoint Security Review 

- An endpoint security review assesses the protections in place for devices like laptops, desktops, mobile phones, and servers (collectively called "endpoints") to ensure they are secure against cyber threats.

#### C1 : Endpoint Controls 

1. List of Installed Applications :
   - Purpose : Review installed applications on an endpoint to identify any unauthorized or non-whitelisted software.
   - Command : Get-Package | Select Name, Version
   - Risk    : Risk of Malwares and Backdoors , increase attack surface
   - Ref     : https://www.youtube.com/watch?v=ildHLspps7M
   - Note    : We can also use Microsoft Intune to fetch list of all installed apps on a device
               (https://learn.microsoft.com/en-us/intune/intune-service/apps/app-discovered-apps)

2. Group policy update status :
   - Purpose : Ensure that the endpoint is receiving and applying group policy updates as expected. This helps enforce security settings such as password policies, firewall rules, software restrictions, and more. 
   - Command : gpresult /r [gpresult /r | findstr /c:"Last time Group Policy was applied:"]
   - Risk    : Missing critical security configurations
   - Note    : Check if it is possible to find status for all devices using Intune?

3. Access to Control Panel :
   - Purpose : Verify whether user access to the Control Panel is restricted. Restricting access helps prevent users from modifying critical system settings that could reduce security posture or bypass enforcement policies.
   - Command : Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction Stop | Select-Object NoControlPanel
      - 1 = Access to Control Panel is blocked ; 0 or missing = Access is allowed 
   - Risk    : If users can access the Control Panel, they may disable security settings, alter network or firewall configurations, install unauthorized software, or modify user accounts.
   - Ref    : https://medium.com/@sanjaykrishna1203/disabling-the-entire-control-panel-in-windows-using-registry-5de95959a919 

4. LM Hash is not stored :
   - Purpose : Ensure that Windows is not storing LAN Manager (LM) password hashes, which are outdated and easily cracked.
   - Command : Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop | Select-Object NoLMHash , LmCompatibilityLevel
      - 1 = LM hash not stored (secure) ; 0 or missing = LM hash may be stored (insecure)
   - Risk    : Can be extracted and brute-forced with minimal resources
   - Note    : Even if LM hash storage is disabled, existing LM hashes remain until users change their passwords, so enforce password changes after disabling LM hashes.

5. Access to CMD :
   - Purpose : Prevent unauthorized users from using the Command Prompt to execute commands, run scripts, or bypass security controls.
   - Command : Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\System' -ErrorAction Stop | Select-Object DisableCMD
      - DisableCMD 1 = disable the prompt and prevent batch files from running ; 2 = to disable the prompt but allow batch files
   - Risk    : If CMD is accessible, malicious users could run system commands, modify configurations, or execute malware payloads.
   - Note    : Need to check manually as since we are running scripts we will have access to CMD and powershell

6. Forced Auto Restarts are Disabled :
   - Purpose : Ensure that automatic restarts after Windows Updates do not occur without user awareness or control.
   - Command : Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction Stop | Select-Object NoAutoRebootWithLoggedOnUsers
   - Risk    : Forced restarts may cause loss of unsaved work and interrupt important tasks or services.
   - Note    : Check if this is implemented via Intune or some other way?

7. Prohibit Software Installations :
   - Purpose : Prevent users from installing unauthorized software, reducing the risk of malware infections, unlicensed software, and policy violations.
   - Command : Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Installer' -ErrorAction Stop | Select-Object DisableMSI 
   - Risk    : Allowing uncontrolled installations increases attack surface, risk of malicious payloads
   - Note    : This only covers MSI-based installs; .exe installers may still run unless blocked by AppLocker, WDAC, or Intune App Protection policies.
               Check Manually by installing exes and also check on crowdstrike portal for blocking

8. User Account Control (UAC) Status :
   - Purpose : Ensure that UAC is enabled to prevent unauthorized changes to the operating system by requiring administrative approval for elevated tasks.
   - Command : Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop 
   - Risk    : Disabling or weakening UAC increases the risk of privilege escalation and unauthorized system modifications.
   - Note    : UAC can be bypassed by some malware if the prompt level is too low, so recommend EnableLUA = 1, PromptOnSecureDesktop = 1, ConsentPromptBehaviorAdmin = 2

9. Access to Powershell :
   - Purpose :
   - Command :
   - Risk    :
   - Note    : Need to check manually as since we are running scripts we will have access to CMD and powershell
    
11. Powershell Auditing (Module Logging , ScriptBlockLogging , System wide Transcription) :
   - Script Block Logging :
      - Purpose : It records code blocks as they are executed, including dynamically generated code. It also records the output path.
      - Command : Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction Stop | Select-Object EnableScriptBlockLogging
      - Risk    : Malicious scripts can go undetected in the system
      - Note    :
         - Enable Protected Event Logging along with Script Block logging cz logging can store sensitive data in logs and if attacker gain access to this logs they may steal data , Protected Event Logging encrypts sensititve data such as usernames , passwords and code logic and can be decrypted later using private key. 
         - EDR like crowdstrike might have these capabilities too //need to do research.
      - Ref     : https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1
      
   - Module Logging : 
      - Purpose : It records the pipeline execution details of PowerShell. This includes the commands which are executed including command invocations and some portion of the scripts. It may not have the entire detail of the execution and the output results.
      - Command : Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction Stop | Select-Object EnableModuleLogging
      - Risk    : Malicious scripts can go undetected in the system 

   - System Wide Transcription :
      - Purpose : Logs both Input and Output of PS scripts , commands into a file 
      - Command : Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction Stop | Select-Object EnableTranscripting, OutputDirectory
      - Risk    : Malicious scripts can go undetected in the system 
      - Note    : If attacker has enough permissions , they can delete the log file

12. Script Execution Policy :
   - Purpose : Ensure PowerShell script execution policy is set to restrict unauthorized or malicious scripts from running.
   - Command : Get-ExecutionPolicy -List
   - Note    : Typical values:
      - Restricted → No scripts can run (most secure, but can break automation)
      - AllSigned → Only scripts signed by a trusted publisher can run (recommended for enterprise)
      - RemoteSigned → Local scripts run, downloaded scripts must be signed (acceptable for many orgs)
      - Unrestricted / Bypass → Scripts can run without restriction (insecure)
   - Risk    : If set to Unrestricted or Bypass, malicious scripts can execute without warning, increasing risk of compromise , For RemoteSigned we can manipulate Zone.Identifier to bypass

13. RDP Checks :
   - Purpose : Ensure RDP is disabled if not required, and if enabled, that Network Level Authentication (NLA) and strong encryption are enforced to prevent unauthorized access and mitigate brute-force/RDP exploitation risks.
   - Commands : 

     
     


