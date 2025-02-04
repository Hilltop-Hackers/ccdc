param([switch]$Elevated)

$user = (whoami).split("\")[1] 


Function Test-Admin { 
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  { 
    if ($elevated) {
         'Tried to elevate, did not work, aborting'
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}


Function Start-PatchServer {
    Disable-PSRemoting -Force
    $TargetDN = ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain).DistinguishedName)
    $ValuedsHeuristics = (Get-ADObject -Identity $TargetDN -Properties dsHeuristics).dsHeuristics
    
    if (($ValuedsHeuristics -eq "") -or ($ValuedsHeuristics.Length -lt 7)) {
        
        Write-Output "Anonymous LDAP access is already disabled."
    
    } elseif (($ValuedsHeuristics.Length -ge 7) -and ($ValuedsHeuristics[6] -eq "2")) {
    
        Write-Output "Warning! Anonymous LDAP access is enabled and authorized on the domain! Value = $ValuedsHeuristics"
    Read-Host 'Press any key to continue... '
    }

    #asrep-roasting patch
    Get-ADUSer -Filter 'DoesNotRequirePreAuth -eq $true ' | Set-ADAccountControl -doesnotrequirepreauth $false

    
$boolssl = Test-Path env:SSLKEYLOGFILE
if ($boolssl -eq 'False') {

    Write-Host 'No SSL key log files found.'

}
if ($boolssl -eq 'True') {

    $holdup = Get-ChildItem env:SSLKEYLOGFILE
    Write-Host 'WARNING: SSL Keys are being logged. The file path is: ' $holdup.Value -ForegroundColor blue -BackgroundColor white
    Write-Host 'Would you like to copy this file to the desktop? (Y/N)' -ForegroundColor blue -BackgroundColor white
$copyssl = Read-Host 'Answer'

if ($copyssl -eq 'Y') {
    $filename = Split-Path $holdup.Value -leaf
    Copy-Item $holdup.Value C:\Users\$user\Desktop\$filename
}

$delssl = Read-Host 'Would you like to remove the environment variable and delete the file path too? (Y/N)'

if ($delssl -eq 'Y') {

    Remove-Item -Path env:SSLKEYLOGFILE
    Remove-Item -Path $holdup.Value
    [Environment]::SetEnvironmentVariable("SSLKEYLOGFILE",$null,"User")
    [Environment]::SetEnvironmentVariable("SSLKEYLOGFILE",$null,"Machine")
    Write-Host 'SSL Key Log File removed.'
}
}
#exploit protection for BinEX
Set-ProcessMitigation -System -Enable DEP
Set-ProcessMitigation -System -Enable CFG
Set-ProcessMitigation -System -Enable SEHOP
Set-ProcessMitigation -System -Enable TerminateOnError
Set-ProcessMitigation -System -Enable BottomUp
Set-ProcessMitigation -System -Enable RequireInfo
Set-ProcessMitigation -System -Enable HighEntropy
Set-ProcessMitigation -System -Enable ForceRelocateImages

Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "ForceDefenderPassiveMode" -Value 0

$rdp = Read-Host '
1. Keep RDP
2. Disable RDP (hey this is probably a better idea)
'
if ($rdp -eq 1) {
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -Value 2
}
if ($rdp -eq 2) {
    #disable remote desktop
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Conferencing" /v "NoRDS" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d 80 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d 0 /f
}

reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" enablesecuritysignature -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force
Set-SmbServerConfiguration -EncryptData $true -Force
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v "TcpReceivePacketSize" /t REG_DWORD /d 0xFF00 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /freg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f

#attempt to start windows defender again
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f

Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
$wsus = Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -ErrorAction SilentlyContinue
if ($wsus) {
$usewsus = (Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver").usewuserver
if ($usewsus -eq '1') {
Write-Host $wsus
Write-Host 'If this contains HTTP, and not HTTPS, you are vulnerable to WSUS poisoning. Please change this to use HTTPS, or remove the WSUS server entirely if it is un-needed.' -BackgroundColor White -ForegroundColor Red
Read-Host "Press enter to continue"
}
}
Write-Host "Fetching the list of services, this may take a while...";
        $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and ($_.State -eq "Running" -or $_.State -eq "Stopped") };
        if ($($services | Measure-Object).Count -lt 1) {
          Write-Host "No unquoted service paths were found";
        }
        else {
          $services | ForEach-Object {
            Write-Host "Unquoted Service Path found! This could lead to local privilege escalation!" -ForegroundColor red
            Write-Host Name: $_.Name
            Write-Host PathName: $_.PathName
            Write-Host StartName: $_.StartName 
            Write-Host StartMode: $_.StartMode
            Write-Host Running: $_.State
          } 
        }
	    Write-Host Press enter to continue...
        Read-Host > wait.txt
		Remove-Item wait.txt

$fwcnf = Read-Host 'Would you like to enable the firewall? Please make sure this works. (Y/N): '
if ($fwcnf -eq 'Y') {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
}

    Start-Process Powershell -verb runas -WindowStyle 1 -PassThru  "dism /online /disable-feature /featurename:SMB1Protocol  /NoRestart"
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    cmd.exe /c 'sc stop remoteregistry'
    cmd.exe /c 'sc config remoteregistry start= disabled' # to facilitate monitoring
}

Function Start-Monitoring {
# Monitor RemoteRegistry Service Status Changes and Check SMB Sessions
$serviceName = "RemoteRegistry"
# WMI Query to detect service state changes
$wmiQuery = @"
SELECT * FROM __InstanceModificationEvent 
WITHIN 2 
WHERE 
    TargetInstance ISA 'Win32_Service' AND 
    TargetInstance.Name = '$serviceName'
"@

# Register the WMI event watcher
$action = {
    $oldState = $event.SourceEventArgs.NewEvent.PreviousInstance.State
    $newState = $event.SourceEventArgs.NewEvent.TargetInstance.State
    
    if ($oldState -ne $newState) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$timestamp] RemoteRegistry status changed from $oldState to $newState"
        
        # Check SMB sessions only when status changes
        $startTime = Get-Date
	$endTime = $startTime.AddSeconds(15)

	while ($endTime -gt (Get-Date)) {




	try {
            $sessions = Get-SmbSession -ErrorAction Stop
            
            if ($sessions) {
                Write-Host "[$timestamp] Active SMB sessions detected:"
                foreach ($session in $sessions) {
                    Write-Host "    User: $($session.ClientUserName)"
                    Write-Host "    Computer: $($session.ClientComputerName)"
                    Write-Host "    Share: $($session.ShareName)"
                    Write-Host "    Duration: $($session.DialectDuration.TotalMinutes) minutes"
                    Write-Host "    ----------"
		    Write-Host "An attacker has gotten access to all of the password hashes. Reset all passwords that you are able to." -ForegroundColor Red -BackgroundColor White
                    Read-Host "Please cancel or close this tab and go fix this"
		}
            }
            else {
                #Write-Host "[$timestamp] No active SMB sessions found"
            }
        }
        catch {
           # Write-Host "[$timestamp] Error checking SMB sessions: $_"
        }
}
    }
}

Register-WmiEvent -Query $wmiQuery -Action $action -ErrorAction Stop | Out-Null

# Keep the script running indefinitely
try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Get-EventSubscriber | Unregister-Event
}
}

Function Start-Downloads {

    # List of URLs to download
$urls = @(
    "https://github.com/SpecterOps/SharpHound/releases/download/v2.5.13/SharpHound-v2.5.13.zip",
    "https://download.sysinternals.com/files/SysinternalsSuite.zip",
    "https://www.voidtools.com/Everything-1.4.1.1026.x86-Setup.exe"
)

# Output directory (modify as needed)
$downloadPath = "C:\Users\$user\Desktop\Downloaded Tools"
New-Item -Path "c:\Users\$user\" -Name "Downloaded Tools" -ItemType "directory"
Add-MpPreference -ExclusionPath $downloadPath
# Loop through each URL
foreach ($url in $urls) {
    try {
        # Extract filename from URL
        $fileName = [System.IO.Path]::GetFileName($url)
        $outputPath = Join-Path -Path $downloadPath -ChildPath $fileName
        
        # Check if file already exists
        if (Test-Path $outputPath) {
            Write-Warning "File already exists: $outputPath"
            continue
        }

        # Download the file
        Write-Host "Downloading: $fileName" -ForegroundColor Cyan
        Invoke-WebRequest -Uri $url -OutFile $outputPath -UseBasicParsing
        
        Write-Host "Successfully downloaded to: $outputPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to download $url : $($_.Exception.Message)"
    }
}
$bhce = Read-Host 'As part of this process, an exclusionary zone was set in Windows Defender for a Bloodhound Collector. Do you want to run that now, and then remove the zone? (Y/N)'
if ($bhce -eq "Y" -or $bche -eq "y") {

Expand-Archive -Path "C:\Users\$user\Desktop\Downloaded Tools\SharpHound-v2.5.13.zip" -DestinationPath "C:\Users\$user\Desktop\Downloaded Tools\Sharphound"
"C:\Users\$user\Desktop\Downloaded Tools\SharpHound-v2.5.13\SharpHound.exe"
Remove-MpPreference -ExclusionPath $downloadPath
}
}

$option = Read-Host '
    What would you like to do? Ensure forensics questions are understood before running the first option.

    1. Patch this machine against local attacks and some network attacks.
    2. Download tools for usage.
    3. Monitor for attacks.
    '

    if ($option -eq 1) {
    Start-PatchServer
    }

    if ($option -eq 2) {
        Start-Downloads
    }

    if ($option -eq 3) {
    $accept = Read-Host 'WARNING: This only monitors for certain common active directory attacks. This is not a one and done solution. Do you want to proceed? (Y/N)'
    
    if ($accept -eq "Y" -or $accept -eq "y") { # i really dont want this to not catch both cases
        Start-Monitoring
    }

}

