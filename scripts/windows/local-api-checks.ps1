# The local API on Windows, checked on Windows (scripts/windows/test-windows.sh runs this in the
# test VM as an administrator). Prints "ok" or "FAIL" lines; another account is played by
# SYSTEM (via Task Scheduler), which is stronger than any other user.
param([string]$Bin = "C:\gmc")
$ErrorActionPreference = "Continue"
$failed = 0
function Check($ok, $what, $detail) {
    if ($ok) { "ok   $what" } else { "FAIL $what :: $detail"; $script:failed++ }
}
$work = "C:\ProgramData\gmc-checks"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $work | Out-Null
function As-System($name, $script) {
    Set-Content "$work\$name.ps1" $script
    $a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File $work\$name.ps1"
    $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "gmc-check-$name" -Action $a -Principal $p -Force | Out-Null
    Start-ScheduledTask -TaskName "gmc-check-$name"
}
function Done($name) {
    Stop-ScheduledTask -TaskName "gmc-check-$name" -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "gmc-check-$name" -Confirm:$false -ErrorAction SilentlyContinue
}

$h = Join-Path $env:TEMP ("gmc-check-" + (Get-Random)); New-Item -ItemType Directory $h | Out-Null
$env:GMC_HOME = $h
$d = Start-Process "$Bin\gmcd.exe" -ArgumentList "--listen","127.0.0.1:47610","--name","VMtest" -PassThru -WindowStyle Hidden -RedirectStandardError "$h.err"
Start-Sleep 8
Check (-not $d.HasExited) "gmcd starts" ((Get-Content "$h.err" -ErrorAction SilentlyContinue) -join " ")
$status = (& "$Bin\gmc.exe" status 2>&1 | ForEach-Object { "$_" }) -join " "
Check ($status -match "\(([A-Z0-9]{4}-){6}[A-Z0-9]{2}\)" -and $status -match "lending:") "gmc reaches gmcd over its pipes" $status
Check ($status -match "Windows Hello") "approvals need Windows Hello" $status

$pipe = (Get-Content "$h\run\control.sock" -Raw).Trim()
Check ($pipe -match '^\\\\\.\\pipe\\gimmecores-[0-9a-f]{32}$') "pipe names are random" $pipe
$acl = ((Get-Acl $pipe).Access | ForEach-Object { $_.IdentityReference.Value + ":" + $_.AccessControlType }) -join ","
Check ($acl -eq "$env:COMPUTERNAME\$env:USERNAME`:Allow") "only this user may open the pipes" $acl
$shared = Get-ChildItem $h -Recurse -File | Where-Object {
    (Get-Acl $_.FullName).Access | Where-Object { $_.IdentityReference -notmatch "$env:USERNAME|SYSTEM|Administrators" }
}
Check (-not $shared) "every file gmcd writes is owner-only" (($shared | ForEach-Object Name) -join ",")

# Another account opens the daemon's pipe.
$name = $pipe.Substring(9)
As-System "open" @"
try { `$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', '$name', [System.IO.Pipes.PipeDirection]::InOut); `$c.Connect(3000); 'OPENED' | Out-File $work\open.txt }
catch { ('refused: ' + `$_.Exception.Message) | Out-File $work\open.txt }
"@
Start-Sleep 10
$open = (Get-Content "$work\open.txt" -ErrorAction SilentlyContinue) -join " "
Check ($open -match "denied") "another account cannot open the daemon's pipe" $open
Done "open"

# Another account serves a pipe anyone may open, and gmc is pointed at it.
$fake = "gimmecores-" + (-join (1..32 | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) }))
As-System "serve" @"
`$ErrorActionPreference = 'Stop'
try {
  `$s = New-Object System.IO.Pipes.PipeSecurity
  `$s.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule('Everyone', 'ReadWrite', 'Allow')))
  `$p = New-Object System.IO.Pipes.NamedPipeServerStream('$fake', [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::None, 4096, 4096, `$s)
  `$p.WaitForConnection()
  `$buf = New-Object byte[] 4096
  "connected; bytes received: `$(`$p.Read(`$buf, 0, 4096))" | Out-File $work\serve.txt
} catch { ('attacker error: ' + `$_.Exception.Message) | Out-File $work\serve.txt }
"@
Start-Sleep 8
$fakeHome = Join-Path $env:TEMP ("gmc-fake-" + (Get-Random)); New-Item -ItemType Directory "$fakeHome\run" | Out-Null
Set-Content "$fakeHome\run\client.sock" ("\\.\pipe\" + $fake)
$env:GMC_HOME = $fakeHome
$said = (& "$Bin\gmc.exe" status 2>&1 | ForEach-Object { "$_" }) -join " "
Start-Sleep 4
$got = (Get-Content "$work\serve.txt" -ErrorAction SilentlyContinue) -join " "
Check ($said -match "another user's program" -and $got -match "bytes received: 0$") "gmc refuses a pipe another account serves, and sends it nothing" "gmc: $said | attacker: $got"
Done "serve"

# A secret readable by everyone.
Stop-Process $d -Force; Start-Sleep 2
icacls "$h\identity.key" /grant "*S-1-1-0:R" | Out-Null
$env:GMC_HOME = $h
$d2 = Start-Process "$Bin\gmcd.exe" -ArgumentList "--listen","127.0.0.1:47611","--name","VMtest" -PassThru -WindowStyle Hidden -RedirectStandardError "$h.err2"
Start-Sleep 6
$err = (Get-Content "$h.err2" -ErrorAction SilentlyContinue) -join " "
Check ($d2.HasExited -and $err -match "may be read by other accounts") "gmcd refuses an identity key others may read" $err
if (-not $d2.HasExited) { Stop-Process $d2 -Force }

Remove-Item $work, $h, $fakeHome -Recurse -Force -ErrorAction SilentlyContinue
if ($failed) { "== $failed check(s) FAILED"; exit 1 } else { "== all local API checks passed" }
