#### C4 : Media & Data Sharing Audit

1. Access to Removable Storage (Along with Read , Write , Execute Access) :
   - Purpose : Verify whether the endpoint blocks or restricts the use of removable storage devices (USB flash drives, external hard drives, SD cards) to prevent data exfiltration and introduction of malware.
   - Command :  Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\*" | Select-Object PSChildName, Deny_Write, Deny_Read, Deny_Execute
   - Note    :
      - If using CrowdStrike, Netskope, or Intune Endpoint Security, removable media control may be enforced via those platforms instead of GPO.
      - To confirm enforcement, try plugging in a test USB device and check if read/write is blocked.

2. Check USBSTOR driver status :
   - Command : Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start"

3. Media Access Audit Logs :
   - Purpose : erify that Windows is logging file and removable media access attempts (Event ID 4663) for security auditing and incident investigation. This helps track potential data theft, malware introduction, or unauthorized file access.
   - Command : Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4663; StartTime=(Get-Date).AddDays(-30)} | Where-Object { $_.Message -like "*Removable*" } | Select-Object TimeCreated, Message

4. Bluetooth File Sharing :
   - Purpose : Ensure Bluetooth data transfer is restricted or disabled to prevent unauthorized wireless data exfiltration or malware delivery via paired devices.
   - Command : Test-Path "C:\Windows\System32\fsquirt.exe" 
   - Note    : Might be enforced via Crowdstrike or Intune so need to check manually , also bluetooth service will be enabled for keyboard , mice but data sharing must be blocked

5. Hotspot Sharing :
   - Purpose : 
   - Command : Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -ErrorAction SilentlyContinue
   - Script :
   ```
   $hotspotCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -ErrorAction SilentlyContinue

   [PSCustomObject]@{
       PolicyConfigured = if ($hotspotCheck) { $true } else { $false }
       HotspotUIBlocked = if ($hotspotCheck.NC_ShowSharedAccessUI -eq 0) { "Yes" } else { "No" }
       VirtualAdapterPresent = if (Get-NetAdapter | Where-Object { $_.Name -like "*Wi-Fi Direct*" }) { "Yes" } else { "No" }
       LastModified = if ($hotspotCheck) { (Get-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections").LastWriteTime } else { "N/A" }
   } | Format-List
   ```


