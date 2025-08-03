#### C5 : OS and FS Audit

1. Unsupported / End-of-Life OS Check :
   - Purpose : Verify that the endpoint is running a supported Windows version, as unsupported OSes no longer receive updates, are prone to exploits, and may not work with modern security tools.
   - Command : Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, InstallDate

2. BIOS info :
   - Command : Get-WmiObject Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate, SerialNumber

3. Is UEFI utilised?
   - Purpose : Verify that the system is using UEFI firmware instead of Legacy BIOS, as UEFI supports Secure Boot, Measured Boot, better BitLocker integration, and modern hardware configurations.
   - Command : ms32info , check bios mode , do manually

4. Filesystem Type and Health Check :
   - Purpose : Ensure the system volume uses a secure and modern filesystem (NTFS or ReFS) rather than FAT32/ExFAT, which lack proper permissions and encryption support.
   - Command : Get-Volume | Select-Object DriveLetter, FileSystem, HealthStatus, SizeRemaining, Size
  
5. BitLocker Full Volume Status (Requires Admin Access):
   - Purpose : Ensure BitLocker full disk encryption is enabled on all fixed drives to protect data at rest.
   - Command : Get-BitLockerVolume | Format-List
  
6. BitLocker Disable Check :
   - Command : Disable-BitLocker -MountPoint "C:"

7. List of Installed Windows Updates :
   - Purpose : Verify that the system is Fully patched with the latest security updates.
   - Command : Get-HotFix | Sort-Object InstalledOn -Descending

8. Check for Pending Reboot :
   - Command : Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"

