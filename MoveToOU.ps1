# Script to move the computer object in AD to the OU supplied as a variable
# Example Command line Powershell.exe -NoProfile -Set-ExecutionPolicy bypass -file MoveToOU.ps1 "%MachineObjectOU%"

$OU = $args[0]

try {
    $CompDN = ([ADSISEARCHER]"sAMAccountName=$($env:COMPUTERNAME)$").FindOne().Path
    $CompObj = [ADSI]"$CompDN"
    $CompObj.psbase.MoveTo([ADSI]"LDAP://$($OU)")
}
catch {
    $_.Exception.Message ; Exit 1
}