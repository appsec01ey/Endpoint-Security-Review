#### C3 : Network Audit 

1. Check  Access to Malicious Domains :
   - Purpose : Verify if the endpoint has security controls (DNS filtering, EDR, web proxy) that block access to known malicious domains.
   - Command :

2. Verify the traffic is flowing through proxy :
   - Note : Here from above output we can potentially verify whether the traffic is flowing through proxy or not
   
4. Cloud Proxy Presence (Zscaler/Netskope/Forcepoint) :
   - Purpose : To check presence of cloud proxy
   - Command : Get-Service | Where-Object { $_.'DisplayName' -match 'Zscaler|Netskope|Forcepoint' -or $_.'Name' -match 'Zscaler|Netskope|Forcepoint' }

5. Check if the Cloud Proxy can be disabled ? :
   - Command :

6. Windows Firewall Status (All Profiles) :
   - Purpose : Ensure that the Windows Defender Firewall is enabled and enforcing rules for all network profiles (Domain, Private, Public). A disabled firewall leaves the endpoint exposed to unauthorized inbound/outbound connections.
   - Command : netsh advfirewall show allprofiles

7.  Active & Listening TCP Connections :
    - Purpose :  Identify open/listening ports and active TCP connections to detect potentially unauthorized services or suspicious remote connections. This can reveal malware, backdoors, or unapproved applications communicating over the network.
    - Command : Get-NetTCPConnection | Where-Object { $_.'State' -eq 'Listen' -or $_.'State' -eq 'Established' } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Format-Table -AutoSize
      
     
