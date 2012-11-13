$server="."
$computer = [ADSI]"WinNT://$server,computer"

$computer.psbase.children | where { $_.psbase.schemaClassName -eq 'group' } | foreach {
    $g_name = $_.name
    $printed = false
    $group =[ADSI]$_.psbase.Path
	$group.psbase.Invoke("Members") | foreach {
		if (! $printed) {
			$printed = true;
			write-host "Group: " $g_name
		}
		write-host " -> Member: " $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
	}
}