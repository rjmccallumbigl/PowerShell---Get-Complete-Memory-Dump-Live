# Declare variables
$baseFolder = "C:\Program Files\Common Files"
$memory = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1MB
$space = (Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }).FreeSpace / 1GB
$dumpLocation = "$($baseFolder)\fullMemory.dmp"

# Download Windows SDK and install debuggers
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12
(New-Object System.Net.WebClient).DownloadFile("https://go.microsoft.com/fwlink/?linkid=2173743", "$($baseFolder)\sdksetup.exe")
if (Test-Path -Path "$($baseFolder)\sdksetup.exe" -PathType Leaf -ErrorAction Stop){
	& "$($baseFolder)\sdksetup.exe" /features "OptionId.WindowsDesktopDebuggers" /l "$($baseFolder)\windowsSDK.log" /quiet /norestart
} else {
	throw "Could not automatically download SDK, please install manually and retry script: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/"		
}

# Download Sysinternals LiveKD for live memory dump
(New-Object System.Net.WebClient).DownloadFile("https://live.sysinternals.com/livekd.exe", "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe")
if (Test-Path -Path "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe" -PathType Leaf -ErrorAction Stop){
	
	# See how much space we need for a complete dump per https://docs.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options#complete-memory-dump
	Write-Output "This server has about $($memory) MB of memory so you will need at least this + 1MB to save the full dump on the drive at $($dumpLocation)." 
	Write-Output "You currently have $($space) GB free on the C: drive."

	if (($memory * 1MB + 1MB) -lt ($space * 1GB)) {
		Write-Output "You have enough space to save the dump, running LiveKD"

		# Seeing if we need to accept EULA before running
		try {
			Get-Item "HKCU:\SOFTWARE\Sysinternals\LiveKd" -ErrorAction Stop
			$eulaResponse = Read-Host "This will attempt to generate a full memory dump without reboot and save it at $($dumpLocation). Type Y or Yes to accept:"
			# Write-Warning "This will attempt to generate a full memory dump without reboot and save it at $($dumpLocation)." -WarningAction Inquire
		}
		catch {
			& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe"
			$eulaResponse = Read-Host "Do you accept the EULA? Type Y or Yes to accept:"
			# Write-Warning "Do you accept the EULA? If you do, this script will attempt to generate a full memory dump without reboot and save it at $($dumpLocation)." -WarningAction Inquire
		}

		if (($eulaResponse -ieq "y") -or ($eulaResponse -ieq "yes")) {
			
			# Check if we're admin before running, if not run as admin 
			if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
				Write-Output "Launching as admin" -
				Start-Process powershell -Verb runAs -ArgumentList "-noexit & 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe' -accepteula -f -o '$dumpLocation'"
				Break
			} else {
				& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe' -accepteula -f -o "$($dumpLocation)"
			}				
		} else {
			throw "Not approved, ending script"
		}		
	} else {
		throw "You do not have enough space to save the dump. You can attach a new disk with available space to the VM and then run the following command via admin PowerShell: ""& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\livekd.exe' -accepteula -f -ml -o '$($dumpLocation)'"""    			
	}
} else {
	throw "Could not automatically download LiveKD, please download manually and retry script: https://live.sysinternals.com/livekd.exe"		
}	