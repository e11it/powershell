# ExportShareInfo.ps1
# This script will export type 0 shares with security info, and provide a hash table of shares
# in which security info could not be found.
#
#reference: http://mow001.blogspot.com/2006/05/powershell-export-shares-and-security.html
#SID was removed from the script. Instead, the username is used to find SID when the import is run

# Allow Set-ExecutionPolicy Unrestricted

# CHANGE TO SERVER THAT HAS SHARES TO EXPORT
$fileServer = Read-Host "Enter Server Name"
#$fileServer = "admin3_n"

$date = get-date
$datefile = get-date -uformat '%m-%d-%Y-%H%M%S'
#$filename = Read-Host "Filename (example: c:\temp\shares.csv)"
$filename = 'c:\'+$fileServer+'.csv'

#Store shares where security cant be found in this hash table
$problemShares = @{}

function Translate-AccessMask($val){ 

    Switch ($val){
    
        2032127 {"FullControl"; break} 
        1179785 {"Read"; break}
        1180063 {"Read, Write"; break} 
        1179817 {"ReadAndExecute"; break}
        -1610612736 {"ReadAndExecuteExtended"; break} 
        1245631 {"ReadAndExecute, Modify, Write"; break}
        1180095 {"ReadAndExecute, Write"; break} 
        268435456 {"FullControl"; break} 
        default {$val; break}
    }
}
Function Get-ShareInfo($shares) {
$arrShareInfo = @()
Foreach ($share in $shares) {
trap{continue;}
write-host $share.name
$strWMI = "\\" + $fileServer + "\root\cimv2:win32_LogicalShareSecuritySetting.Name='" + $share.name + "'"
$objWMI_ThisShareSec = $null
$objWMI_ThisShareSec = [wmi]$strWMI

#In case the WMI query or 'GetSecurityDescriptor' fails, we retry a few times before adding to 'problem shares'
For($i=0;($i -lt 5) -and ($objWMI_ThisShareSec -eq $null);$i++) {
sleep -milliseconds 200
$objWMI_ThisShareSec = [wmi]$strWMI
}
$objWMI_SD = $null
$objWMI_SD = $objWMI_ThisShareSec.invokeMethod('GetSecurityDescriptor',$null,$null)
For($j=0;($j -lt 5) -and ($objWMI_SD -eq $null);$j++) {
sleep -milliseconds 200
$objWMI_SD = $objWMI_ThisShareSec.invokeMethod('GetSecurityDescriptor',$null,$null)
}
If($objWMI_SD -ne $null) {
$arrShareInfo += $objWMI_SD.Descriptor.DACL | % {
$_ | select @{e={$share.name};n='Name'},
@{e={$share.Path};n='Path'},
@{e={$share.Description};n='Description'},
AccessMask,
AceFlags,
AceType,
@{e={$_.trustee.Name};n='User'},
@{e={$_.trustee.Domain};n='Domain'}
}
}
Else {
$ProblemShares.Add($share.name, "failed to find security info")
}
}
return $arrshareInfo
}

Write-Host "Finding Share Security Information"

# get Shares (Type 0 is "Normal" shares) # can filter on path, etc. with where
$shares = gwmi Win32_Share -computername $fileServer -filter 'type=0'
# get the security info from shares, add the objects to an array
Write-Host " Complete" -ForegroundColor green
Write-Host "Preparing Security Info for Export"

$ShareInfo = Get-ShareInfo($shares)

Write-Host " Complete" -ForegroundColor green

Write-Host " Rewrite share permission to human readable"
Foreach ($sh in $ShareInfo) {
	$newAccessMask =  Translate-AccessMask( $sh.AccessMask )
	$sh.AccessMask = $newAccessMask
}
Write-Host "Exporting to CSV"

# Export them to CSV
$ShareInfo | select Name,Path,Description,User,Domain,
AccessMask,AceFlags,AceType | export-csv -noType $filename -Encoding "UTF8"

Write-Host " Complete" -ForegroundColor green
Write-Host "Your file has been saved to $filename"
If ($problemShares.count -ge 1) {
Write-Host "These Shares Failed to Export:"
}
$problemShares
