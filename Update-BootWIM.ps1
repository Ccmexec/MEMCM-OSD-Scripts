<#
    Stripped down script from https://learn.microsoft.com/en-us/windows/deployment/update/media-dynamic-update
    to update WinPE/boot image/boot.wim.
    You need to download the approproiate CU for the boot image version you are using.
    Copy the CU to $LCU_PATH. Copy your boot.wim file to $BOOT_WIM.

    Version 0.1 - 2023-05-10
    Sassan Fanai

#>

#Requires -RunAsAdministrator

function Get-TS { return "{0:HH:mm:ss}" -f [DateTime]::Now }

Write-Output "$(Get-TS): Starting media refresh"

# Declare Dynamic Update packages
$LCU_PATH        = "C:\mediaRefresh\packages\LCU.msu"
$BOOT_WIM        = "C:\Boot Image Backup\boot.wim"

# Declare folders for mounted images and temp files
$WORKING_PATH    = "C:\mediaRefresh\temp"
$WINPE_MOUNT     = "C:\mediaRefresh\temp\WinPEMount"

# Check for LCU MSU
if (!(Test-Path $LCU_PATH)) {
    Write-Output "$(Get-TS): No LCU.msu found. You nned to download and copy the CU for your boot image version to $LCU_PATH and rename the file to LCU.msu"
    break
}

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
    Write-Output "$(Get-TS): Mounting WinPE, image index $($IMAGE.ImageIndex)"
    Mount-WindowsImage -ImagePath $BOOT_WIM  -Index $IMAGE.ImageIndex -Path $WINPE_MOUNT -ErrorAction stop | Out-Null

    try
    {
        Write-Output "$(Get-TS): Adding package $LCU_PATH"
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
    Write-Output "$(Get-TS): Exporting image to $WORKING_PATH\boot2.wim"
    Export-WindowsImage -SourceImagePath $BOOT_WIM  -SourceIndex $IMAGE.ImageIndex -DestinationImagePath $WORKING_PATH"\boot2.wim" -ErrorAction stop | Out-Null

}

Move-Item -Path $WORKING_PATH"\boot2.wim" -Destination $BOOT_WIM  -Force -ErrorAction stop | Out-Null