# Script to add the computername on which the script is executed on to specified groups.
# Example Command line with Powershell.exe -NoProfile -ExecutionPolicy Bypass –File AddToGroups.Ps1 “group1”:”group2”

$Groups = $args[0].Split(':')

foreach($Group in $Groups) {

    try {

        $ComputerDn = ([ADSISEARCHER]"sAMAccountName=$($env:COMPUTERNAME)$").FindOne().Path
        $GroupDn = ([ADSISEARCHER]"sAMAccountName=$($Group)").FindOne().Path
        $Group = [ADSI]"$GroupDn"

        if(!$Group.IsMember($ComputerDn)) {
            $Group.Add($ComputerDn)
        }
    }
    catch {
        $_.Exception.Message ; Exit 1
    }
}