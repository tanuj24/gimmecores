# Core local-API checks as an ordinary (not elevated) desktop session.
$o = "C:\gmc\unelevated.txt"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"elevated: $admin" | Out-File $o
$h = Join-Path $env:TEMP ("gmc-unelev-" + (Get-Random)); New-Item -ItemType Directory $h | Out-Null
$env:GMC_HOME = $h
$d = Start-Process "C:\gmc\gmcd.exe" -ArgumentList "--listen","127.0.0.1:47640","--name","Unelevated" -PassThru
Start-Sleep 8
"gmcd running: " + (-not $d.HasExited) | Out-File -Append $o
"gmc status: " + ((& "C:\gmc\gmc.exe" status 2>&1 | Select-Object -First 1) -join "") | Out-File -Append $o
$pipe = (Get-Content "$h\run\control.sock" -Raw).Trim()
"pipe access: " + (((Get-Acl $pipe).Access | ForEach-Object { $_.IdentityReference.Value + ":" + $_.AccessControlType }) -join ",") | Out-File -Append $o
$shared = Get-ChildItem $h -Recurse -File | Where-Object { (Get-Acl $_.FullName).Access | Where-Object { $_.IdentityReference -notmatch "$env:USERNAME|SYSTEM|Administrators" } }
"files others may read: " + $(if ($shared) { ($shared | ForEach-Object Name) -join "," } else { "none" }) | Out-File -Append $o
Stop-Process $d -Force
Remove-Item $h -Recurse -Force -ErrorAction SilentlyContinue
"done" | Out-File -Append $o
