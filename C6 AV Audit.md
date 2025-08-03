#### C1 : AV Audit

1. Installed Antivirus Products :
   - Command : Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntivirusProduct | Select-Object displayName, pathToSignedProductExe, productState

2. Scheduled Scan Policy :
   - Purpose : Verify that antivirus/endpoint protection is configured to automatically scan the system on a regular schedule (daily/weekly) to detect dormant threats.
   - Command : Get-MpPreference | Select-Object ScanScheduleDay, ScanScheduleTime, ScanScheduleType
   - Note    : We can only check for MS Defender , for EDR like Crowdstrike we need to check on console manually

3. On-Access Scan Policy :
   - Purpose : Ensure that antivirus actively scans files as they are accessed or modified, blocking threats in real time.
   - Command : Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, OnAccessProtectionEnabled
   - Note    : We can only check for MS Defender , for EDR like Crowdstrike we need to check on console manually

4. Signature Definition Update Policy
   - Purpose : Ensure that antivirus/endpoint protection is configured to automatically update malware signature definitions so it can detect the latest threats.
   - Command : Get-MpPreference | Select-Object SignatureUpdateInterval, SignatureScheduleDay, SignatureUpdateCatchupInterval, SignatureFallbackOrder, SignatureDefinitionUpdateFileSharesSource, DisableAutoUpdate, CheckForSignaturesBeforeRunningScan, SignaturesUpdatesDays
   - Note    : We can only check for MS Defender , for EDR like Crowdstrike we need to check on console manually

5. Current Signature Update Status :
   - Purpose : Ensure that endpoints are actually receiving and applying signature updates.
   - Command : Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated, AntivirusSignatureVersion

