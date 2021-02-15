# Script to set the Computer description in AD for the computer on which it is executed from.
# Example Command line Powershell.exe -Set-ExecutionPolicy bypass -file .\SetComputerDesc "Computer Description"

[string]$Description = $args[0]

    try {

        $ComputerDn = ([ADSISEARCHER]"sAMAccountName=$($env:COMPUTERNAME)$").FindOne().Path
        $ADComputer = [ADSI]$ComputerDn
        $ADComputer.description = $Description
        $ADComputer.SetInfo()

    }
    catch {
        $_.Exception.Message ; Exit 1
    }