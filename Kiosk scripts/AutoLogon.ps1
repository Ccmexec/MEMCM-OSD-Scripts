# Name: Autologon
# Authors: Jörgen Nilsson
# ccmexec.com

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [string]$Username,
    [Parameter(Mandatory=$True)]
    [string]$Password
  )
# Logon domain
$Domain="demiranda"

# Creates ScheduleTask
Register-ScheduledTask -Xml (get-content $PSScriptRoot\autologon.xml | out-string) -TaskName "Autologon"

# Copy Autologon.exe
Copy-Item -path $PSScriptRoot\autologon.exe -Destination C:\Windows

# Creates the autologon.cmd file
$AutologonFile = "C:\Windows\temp\Autologon.cmd"
New-Item $AutologonFile -ItemType File -Value "C:\Windows\Autologon.exe /accepteula $Username $Domain $Password"
Add-Content $AutologonFile ""
Add-Content $AutologonFile "del C:\Windows\Autologon.exe"
Add-Content $AutologonFile "schtasks.exe /delete /tn AutoLogon /f"
Add-Content $AutologonFile "shutdown /r /t 20 /f"
Add-Content $AutologonFile "del %0" 

# Sets permissions so only System can read the cmd file
Invoke-Expression -Command:"icacls C:\Windows\Temp\Autologon.cmd /inheritance:r"
Invoke-Expression -Command:"icacls C:\Windows\Temp\Autologon.cmd /grant SYSTEM:'(F)'"
