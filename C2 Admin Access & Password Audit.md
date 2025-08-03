
#### C2 : Admin Access and Password Audit

1. List of local Users :
   - Purpose : Identify all local accounts on the endpoint to ensure there are no unauthorized, legacy, or inactive accounts that could be exploited.
   - Command : Get-LocalUser | Select Name, SID , Enabled

2. List of users with admin access
   - Purpose : Identify users with priviledged access
   - Command : Get-LocalGroupMember -Group "Administrators"

3. List of all Groups and its Members :
   - Purpose : Identify all groups and its members
   - Command :  Get-LocalGroup | % { $g=$_.Name; if($m=@(Get-LocalGroupMember -Group $g -EA 0)) {$m|Select @{n='Group';e={$g}},Name,ObjectClass} else {[PSCustomObject]@{Group=$g;Name='(No members)';ObjectClass='N/A'}} }

4. Check if Guest ID is enabled or not :
   - Purpose : Ensure the built-in Guest account is disabled. The Guest account is a well-known local account with no password by default and is often targeted for unauthorized access.
   - Command : Get-LocalUser | Where-Object { $_.SID -match '-501$' } | Select Name, Enabled, SID
   - Note    : Here don't check by name as guest user may have a diff name , check based on SID [501]

5. Local Password Policy :
   - Purpose :  Ensure the system enforces a strong password policy to reduce the risk of brute-force or dictionary attacks
   - Command :  net accounts

6. Domain Password Policy :
   - Note    : Check via GPO Backup or DC

7. LAPS Check :
   - Purpose : Verify if Microsoft LAPS is deployed to manage local administrator passwords securely.
LAPS automatically generates unique, complex local admin passwords and stores them in Active Directory (or Entra ID in newer versions), reducing the risk of lateral movement from reused passwords.
   - Command :
       1. Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue
       2. Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS" -ErrorAction SilentlyContinue

8. Audit Policy Review :
   - Purpose : Ensure advanced audit policies are configured to log important security events such as logons, privilege use, account management, and process execution. Proper auditing is essential for detecting suspicious activities and supporting forensic investigations.
   - Command : auditpol /get /category:* [Requires admin access so run separately]



