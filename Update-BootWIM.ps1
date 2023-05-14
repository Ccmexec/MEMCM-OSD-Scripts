<#
    Stripped down version of https://learn.microsoft.com/en-us/windows/deployment/update/media-dynamic-update
    to update WinPE/boot image/boot.wim.
    You need to download the approproiate CU for the boot image version you are using.

    Version 0.2 - 2023-05-14
    Sassan Fanai
#>

#Requires -RunAsAdministrator

param (
    $UpdateFile = "C:\mediaRefresh\packages\LCU.msu",
    $WimFile = "C:\Boot Image Backup\boot.wim",
    $StagingPath = "C:\mediaRefresh\Temp"
)

function Get-TS { return "{0:HH:mm:ss}" -f [DateTime]::Now }

if (!(Test-Path $UpdateFile)) {
    Write-Output "$(Get-TS): No update file found @ [$UpdateFile]. Exiting..."
    break
}

if (!(Test-Path $WimFile)) {
    Write-Output "$(Get-TS): No WIM file found @ [$WimFile]. Exiting..."
    break
}

Write-Output "$(Get-TS): Starting media refresh of [$WimFile]"

# Declare Dynamic Update packages
$LCU_PATH        = $UpdateFile
$BOOT_WIM        = $WimFile

# Declare folders for mounted images and temp files
$WORKING_PATH    = "$StagingPath"
$WINPE_MOUNT     = "$StagingPath\WinPEMount"


# Create folders for mounting images and storing temporary files
if (!(Test-Path $WORKING_PATH)) {
    New-Item -ItemType directory -Path $WORKING_PATH -ErrorAction Stop | Out-Null
}
if (!(Test-Path $WINPE_MOUNT)) {
    New-Item -ItemType directory -Path $WINPE_MOUNT  -ErrorAction stop | Out-Null
}

#
# update Windows Preinstallation Environment (WinPE)
#

# Get the list of images contained within WinPE
$WINPE_IMAGES = Get-WindowsImage -ImagePath $BOOT_WIM

Foreach ($IMAGE in $WINPE_IMAGES) {

    # update WinPE
    Write-Output "$(Get-TS): Mounting WinPE, image index [$($IMAGE.ImageIndex)]"
    Mount-WindowsImage -ImagePath $BOOT_WIM  -Index $IMAGE.ImageIndex -Path $WINPE_MOUNT -ErrorAction stop | Out-Null

    try
    {
        Write-Output "$(Get-TS): Adding package [$LCU_PATH]"
        Add-WindowsPackage -Path $WINPE_MOUNT -PackagePath $LCU_PATH | Out-Null
    }
    Catch
    {
        $theError = $_
        Write-Output "$(Get-TS): $theError"

        if ($theError.Exception -like "*0x8007007e*") {
            Write-Output "$(Get-TS): This failure is a known issue with combined cumulative update, we can ignore."
        }
        else {
            throw
        }
    }

    # Perform image cleanup
    Write-Output "$(Get-TS): Performing image cleanup on WinPE"
    DISM /image:$WINPE_MOUNT /cleanup-image /StartComponentCleanup | Out-Null

    # Dismount
    Dismount-WindowsImage -Path $WINPE_MOUNT -Save -ErrorAction stop | Out-Null

    #Export WinPE
    Write-Output "$(Get-TS): Exporting image to [$WORKING_PATH\boot2.wim]"
    Export-WindowsImage -SourceImagePath $BOOT_WIM -SourceIndex $IMAGE.ImageIndex -DestinationImagePath $WORKING_PATH"\boot2.wim" -ErrorAction stop | Out-Null
}

Write-Output "$(Get-TS): Moving updated and exported boot2.wim from staging area [$StagingPath] to [$BOOT_WIM]"
Move-Item -Path $WORKING_PATH"\boot2.wim" -Destination $BOOT_WIM  -Force -ErrorAction stop | Out-Null
