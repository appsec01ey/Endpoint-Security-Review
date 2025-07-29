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
   - Command : Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop | Select-Object NoLMHash
      - 1 = LM hash not stored (secure) ; 0 or missing = LM hash may be stored (insecure)
   - Risk    : Can be extracted and brute-forced with minimal resources
   - Note    : Even if LM hash storage is disabled, existing LM hashes remain until users change their passwords, so enforce password changes after disabling LM hashes.

5. Access to CMD :
   - Purpose : 
   - Command :
   - Risk    :
   - Note    : Need to check manually as since we are running scripts we will have access to CMD and powershell

6. Forced Auto Restarts are Disabled :
   - Purpose : Ensure that automatic restarts after Windows Updates do not occur without user awareness or control.
   - Command : Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction Stop | Select-Object NoAutoRebootWithLoggedOnUsers
   - Risk    : Forced restarts may cause loss of unsaved work and interrupt important tasks or services.
   - Note    : Check if this is implemented via Intune or some other way?

7. 
     


