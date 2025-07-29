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
   - Purpose : 
   - Command :
   - Risk    :

4. LM Hash is not stored :
   - Purpose : 
   - Command :
   - Risk    :
