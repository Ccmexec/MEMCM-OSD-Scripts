$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
$BootImageID = "_SMSTSHTTP" + $tsenv.Value('_SMSTSBootImageID')
$BootImageDPs = $tsenv.Value($BootImageID)
$servers = @()
 
foreach ($location in $BootImageDPs.Split(',')) {
    $url = "{0}/{1}/{2}" -f $location.Split('/').Trim()
    $server = $url.Replace("HTTPS://", "").Replace("HTTP://", "").Replace("https://", "").Replace("http://", "")
    $servers += $server
}
$uniqueLocations = $servers | select -Unique
$struniqueLocations = $uniqueLocations -join ","
$tsenv.Value('OSDDPS') = $struniqueLocations
