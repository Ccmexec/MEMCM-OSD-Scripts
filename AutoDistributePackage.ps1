<#
    Scipt: AutoDistributePackages.ps1
    Version: 1.0
    Author: Johan Schrewelius, Onevinn AB
    Date: 2017-03-05
    Usage: Invoke by SCCM Status Filter Rule to automatically Distribute new Packages.
    Status Message ID: 30000
    Command: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -executionpolicy bypass -file "<Path to script>\AutoDistributePackages.ps1" %msgis02
    Limitations: Designed to run on Primary Site Server (SMS Provider).
    Config:
        $CopyToShare = [$True | $False] - If package should be marked "Copy the content in this package to a package share....."
        $DPgroups = [@() = Don't distribute content] | @("<Name of Distribution Point Group 1>", "<Name of Distribution Point Group 2>") = List of Distribution point GROUPS]
#>

Param(
[string]$PackageID
)

# CONFIG START

$CopyToShare = $True
$DPgroups = @("All DP")

# CONFIG END

import-module $env:SMS_ADMIN_UI_PATH.Replace("bin\i386","bin\ConfigurationManager.psd1") -force

$SiteCode = $(Get-WMIObject -ComputerName “$ENV:COMPUTERNAME” -Namespace “root\SMS” -Class “SMS_ProviderLocation”).SiteCode
new-psdrive -Name $SiteCode -PSProvider “AdminUI.PS.Provider\CMSite” -Root “$ENV:COMPUTERNAME” -Description “SCCM Primary Site”
Set-Location “$SiteCode`:”

$CMPackage = Get-CMPackage -Id $PackageID
$CMDriverPackage = Get-CMDriverPackage -Id $PackageID
$CMOSImage = Get-CMOperatingSystemImage -Id $PackageID

if($CMPackage) {

    if($CopyToShare) {
        $result = Set-CMPackage -Id $PackageID -CopyToPackageShareOnDistributionPoints $True -ErrorAction SilentlyContinue
    }

    $DPgroups |% {
        $result = Start-CMContentDistribution –PackageID $PackageID –DistributionPointGroupName "$_" -ErrorAction SilentlyContinue
    }
}

if($CMDriverPackage) {

    if($CopyToShare) {
        $result = Set-CMDriverPackage -Id $PackageID -CopyToPackageShareOnDistributionPoints $True -ErrorAction SilentlyContinue
    }

    $DPgroups |% {
        $result = Start-CMContentDistribution -DriverPackageId $PackageID –DistributionPointGroupName "$_" -ErrorAction SilentlyContinue
    }
}

if($CMOSImage) {

    if($CopyToShare) {
        $result = Set-CMOperatingSystemImage -Id $PackageID -CopyToPackageShareOnDistributionPoints $True -ErrorAction SilentlyContinue
    }

    $DPgroups |% {
        $result = Start-CMContentDistribution -OperatingSystemImageId $PackageID –DistributionPointGroupName "$_" -ErrorAction SilentlyContinue
    }
}

