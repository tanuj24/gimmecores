# Runs a program in the signed-in desktop session (not this SSH session): desk.ps1 <exe> [args...]
param([string]$Exe, [string]$Arguments = "")
$a = if ($Arguments) { New-ScheduledTaskAction -Execute $Exe -Argument $Arguments } else { New-ScheduledTaskAction -Execute $Exe }
$p = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
$t = "gmc-desk-" + (Get-Random)
Register-ScheduledTask -TaskName $t -Action $a -Principal $p -Force | Out-Null
Start-ScheduledTask -TaskName $t
Start-Sleep 2
Unregister-ScheduledTask -TaskName $t -Confirm:$false
