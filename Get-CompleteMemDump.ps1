<###################################################################################################

.SYNOPSIS
    Grab a complete memory dump without rebooting.
.DESCRIPTION
    Grab a complete memory dump without rebooting. Checks drive space and memory size prior to running. Grabs tools from Windows SDK and Sysinternal automatically. Requires outbound connectivity.
.INPUTS
	N/A
.OUTPUTS
	None directly, but creates a .dmp file in "C:\Program Files\Common Files" by default.
.EXAMPLE
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12;iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/rjmccallumbigl/PowerShell---Get-Complete-Memory-Dump-Live/main/Get-CompleteMemDump.ps1'))
.LINK
	https://github.com/rjmccallumbigl/PowerShell---Get-Complete-Memory-Dump-Live
.NOTES
    Author: Ryan McCallum
    Last Modified: 05-27-2022
    v0.1.5

####################################################################################################>

# Declare variables
$baseFolder = "C:\Program Files\Common Files"
$memory = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1MB
$space = (Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }).FreeSpace / 1GB
$dumpLocation = "$($baseFolder)\fullMemory.dmp"

# https://stackoverflow.com/a/49307332/7954017
Write-Output "Disabling IE Enhanced Security Configuration..."
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
Rundll32 iesetup.dll, IEHardenLMSettings
Rundll32 iesetup.dll, IEHardenUser
Rundll32 iesetup.dll, IEHardenAdmin
Write-Output "IE Enhanced Security Configuration has been disabled."

# Download Windows SDK and install debuggers
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
(New-Object System.Net.WebClient).DownloadFile("https://go.microsoft.com/fwlink/?linkid=2173743", "$($baseFolder)\sdksetup.exe")
if (Test-Path -Path "$($baseFolder)\sdksetup.exe" -PathType Leaf -ErrorAction Stop) {
	& "$($baseFolder)\sdksetup.exe" /features "OptionId.WindowsDesktopDebuggers" /l "$($baseFolder)\windowsSDK.log" /quiet /norestart
}
else {
	throw "Could not automatically download SDK, please install manually and retry script: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/"
}

# Download Sysinternals LiveKD for live memory dump
(New-Object System.Net.WebClient).DownloadFile("https://live.sysinternals.com/livekd.exe", "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe")
if (Test-Path -Path "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe" -PathType Leaf -ErrorAction Stop) {

	# See how much space we need for a complete dump per https://docs.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options#complete-memory-dump
	Write-Output "This server has about $($memory) MB of memory so you will need at least this + 256MB + 1MB to save the full dump on the drive at $($dumpLocation)."
	Write-Output "You currently have $($space) GB free on the C: drive."

	if (($memory * 1MB + 257MB) -lt ($space * 1GB)) {
		Write-Output "You have enough space to save the dump, running LiveKD"

		# Seeing if we need to accept EULA before running
		try {
			Get-Item "HKCU:\SOFTWARE\Sysinternals\LiveKd" -ErrorAction Stop
			Write-Warning "This will attempt to generate a full memory dump without reboot and save it at $($dumpLocation)." -WarningAction Inquire
		}
		catch {
			& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe"
			Write-Warning "Do you accept the EULA (https://docs.microsoft.com/en-us/sysinternals/license-terms)? If you do, this script will attempt to generate a full memory dump without reboot and save it at $($dumpLocation)." -WarningAction Inquire
		}

		Write-Warning "Press Y on the next prompt to reference the Microsoft symbol server."

		# Check if we're admin before running, if not run as admin
		if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
			Write-Output "Launching as admin"
			Start-Process powershell -Verb runAs -ArgumentList "-noexit & 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe' -accepteula -f -p -o '$dumpLocation'"
			Break
		}
		else {
			& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe' -accepteula -f -p -o "$($dumpLocation)"

            # When complete, run dumpchk to verify integrity of dump file
            & "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dumpchk.exe" "$($dumpLocation)"

            if (!$?){
                Write-Warning "The dumpchk was not successful, dump may be invalid!"
            }

            Write-Output "Process complete, dump saved to $($dumpLocation)."

		}
	}
 else {
		throw "You do not have enough space to save the dump. You can attach a new disk with available space to the VM and then run the following command via admin PowerShell: ""& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe' -accepteula -f -p -o '$($dumpLocation)'"" but change the location to the new drive"
	}
}
else {
	throw "Could not automatically download LiveKD, please download manually and retry script: https://docs.microsoft.com/en-us/sysinternals/downloads/livekd"
}
