# Script to remove the computername on which the script is executed on from specified groups
# Example Command line Powershell.exe -NoProfile -ExecutionPolicy Bypass –File RemoveADGroup.ps1 “group1”:”group2”

$Groups = $args[0].Split(':')

foreach($Group in $Groups) {

    try {

        $ComputerDn = ([ADSISEARCHER]"sAMAccountName=$($env:COMPUTERNAME)$").FindOne().Path
        $GroupDn = ([ADSISEARCHER]"sAMAccountName=$($Group)").FindOne().Path
        $Group = [ADSI]"$GroupDn"

        if($Group.IsMember($ComputerDn)) {
            $Group.Remove($ComputerDn)
        }
    }
    catch {
        $_.Exception.Message ; Exit 1
    }
}