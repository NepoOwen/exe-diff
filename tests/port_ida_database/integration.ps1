param(
	[string]$Exediff = (Join-Path $PSScriptRoot '..\..\build\exediff.exe'),
	[string]$Scratch = (Join-Path $env:TEMP 'port-ida-database-it'),
	[string]$Launcher = (Join-Path $PSScriptRoot '..\..\scripts\port-ida-database\port-ida-database.ps1'),
	[string]$IdaDir
)

$project = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$Exediff = [System.IO.Path]::GetFullPath($Exediff)
$Launcher = [System.IO.Path]::GetFullPath($Launcher)
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Step($text) { Write-Host "== $text" -ForegroundColor White }
function Stop-Run($text) { Write-Host "FAIL $text" -ForegroundColor Red; exit 1 }

function Find-Ida {
	$candidates = @()
	if ($IdaDir) { $candidates += $IdaDir }
	$ini = Join-Path (Split-Path $Exediff -Parent) 'exediff.ini'
	if (Test-Path -LiteralPath $ini) {
		foreach ($line in [System.IO.File]::ReadAllLines($ini)) {
			if ($line -match '^\s*ida_dir\s*=\s*"?([^"]*?)"?\s*$' -and $Matches[1]) { $candidates += $Matches[1] }
		}
	}
	if ($env:IDADIR) { $candidates += $env:IDADIR }
	$candidates += @(Get-ChildItem -LiteralPath $env:ProgramFiles -Directory -Filter 'IDA*' | Sort-Object Name -Descending | ForEach-Object { $_.FullName })
	foreach ($c in $candidates) { if (Test-Path -LiteralPath (Join-Path $c 'idat.exe')) { return $c } }
	Stop-Run 'IDA Pro not found: pass -IdaDir'
}

function Invoke-Idat($script, $db, $name, $scriptArgs = '') {
	$stdin = Join-Path $Scratch 'stdin.txt'
	[System.IO.File]::WriteAllText($stdin, '')
	$log = Join-Path $Scratch "$name.ida.log"
	if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log }
	$extra = if ($scriptArgs) { ' ' + $scriptArgs } else { '' }
	$argText = '-A -L"' + $log + '" -S"\"' + $script + '\"' + $extra + '" "' + $db + '"'
	$p = Start-Process -FilePath $idat -ArgumentList $argText -NoNewWindow -PassThru -RedirectStandardInput $stdin `
		-RedirectStandardOutput (Join-Path $Scratch "$name.out.txt") -RedirectStandardError (Join-Path $Scratch "$name.err.txt")
	$null = $p.Handle
	if (-not $p.WaitForExit(30 * 60 * 1000)) { $p.Kill(); Stop-Run "${name}: idat did not finish in 30 minutes" }
	return $p.ExitCode
}

function Copy-Db($from, $to) {
	foreach ($ext in '.i64', '.id0', '.id1', '.id2', '.nam', '.til') {
		$p = [System.IO.Path]::ChangeExtension($to, $ext)
		if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
	}
	Copy-Item -LiteralPath $from -Destination $to
}

function Run-Launcher($name, [string[]]$launcherArgs) {
	$text = (& powershell -NoProfile -ExecutionPolicy Bypass -File $Launcher @launcherArgs 2>&1 | Out-String)
	$code = $LASTEXITCODE
	[System.IO.File]::WriteAllText((Join-Path $Scratch "$name.launcher.txt"), $text, $utf8)
	foreach ($l in ($text.TrimEnd() -split "`r?`n")) { Write-Host "   $l" }
	return @{ code = $code; text = $text }
}

function Add-Check($name, $ok, $why) {
	$line = if ($ok) { "CHECK ok $name" } else { "CHECK FAIL ${name}: $why" }
	[System.IO.File]::AppendAllText($checkFile, $line + "`n", $utf8)
}

function Hash($path) { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }

if (-not (Test-Path -LiteralPath $Scratch)) { [void](New-Item -ItemType Directory -Path $Scratch) }
$Scratch = [System.IO.Path]::GetFullPath($Scratch)
$ida = Find-Ida
$idat = Join-Path $ida 'idat.exe'
$out = Join-Path $Scratch 'out'
$checkFile = Join-Path $Scratch 'check.txt'
if (Test-Path -LiteralPath $checkFile) { Remove-Item -LiteralPath $checkFile }
$sw = [System.Diagnostics.Stopwatch]::StartNew()

Step "exediff (the first run analyses both exes with IDA and takes minutes)"
$exediffLog = Join-Path $Scratch 'exediff.txt'
& $Exediff (Join-Path $project 'Trove_x64.old.exe') (Join-Path $project 'Trove_x64.new.exe') --out $out --work (Join-Path $Scratch 'work') --ida $ida *> $exediffLog
if ($LASTEXITCODE -ne 0) { Get-Content -LiteralPath $exediffLog -Tail 10 | ForEach-Object { Write-Host "   $_" }; Stop-Run "exediff exit $LASTEXITCODE" }

$pair = @{}
foreach ($line in [System.IO.File]::ReadAllLines((Join-Path $out 'pair.txt'), $utf8)) {
	$eq = $line.IndexOf('=')
	if ($eq -gt 0) { $pair[$line.Substring(0, $eq)] = $line.Substring($eq + 1).Trim() }
}
$cachedOld = Join-Path $pair['old_work'] 'input.exe.i64'
$cachedNew = Join-Path $pair['new_work'] 'input.exe.i64'
foreach ($db in $cachedOld, $cachedNew) { if (-not (Test-Path -LiteralPath $db)) { Stop-Run "no analysed database at $db" } }

$fixture = Join-Path $Scratch 'fixture.json'
foreach ($f in $fixture, ($fixture + '.error.txt')) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f } }
$env:EXEDFIX_FIXTURE = $fixture
$env:PORTDB_MAP = Join-Path $out 'map.csv'
$env:PORTDB_PAIR = Join-Path $out 'pair.txt'
$env:EXEDFIX_NEWSHAPES = Join-Path $Scratch 'new_shapes.json'
$env:EXEDFIX_NEWDATA = Join-Path $Scratch 'new_data.json'
foreach ($f in $env:EXEDFIX_NEWSHAPES, $env:EXEDFIX_NEWDATA) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f } }

Step 'fixture: the instructions of the changed functions in a copy of the analysed new database'
$shapesDb = Join-Path $Scratch 'new_shapes.i64'
Copy-Db $cachedNew $shapesDb
$code = Invoke-Idat (Join-Path $PSScriptRoot 'make_fixture.py') $shapesDb 'shapes-fixture' '--new-shapes'
foreach ($ext in '.i64', '.id0', '.id1', '.id2', '.nam', '.til') {
	$p = [System.IO.Path]::ChangeExtension($shapesDb, $ext)
	if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}
if ($code -ne 0 -or -not (Test-Path -LiteralPath $env:EXEDFIX_NEWSHAPES) -or -not (Test-Path -LiteralPath $env:EXEDFIX_NEWDATA) -or (Test-Path -LiteralPath ($fixture + '.error.txt'))) { Stop-Run "make_fixture.py --new-shapes exit $code, see $Scratch\shapes-fixture.ida.log" }

Step 'fixture: annotate a copy of the analysed old database'
$annotated = Join-Path $Scratch 'old_annotated.i64'
Copy-Db $cachedOld $annotated
$code = Invoke-Idat (Join-Path $PSScriptRoot 'make_fixture.py') $annotated 'fixture'
if ($code -ne 0 -or -not (Test-Path -LiteralPath $fixture)) { Stop-Run "make_fixture.py exit $code, see $Scratch\fixture.ida.log" }

Step 'fixture: a variant of the new database (a name clash, a deleted function)'
$variantDb = Join-Path $Scratch 'new_variant.i64'
Copy-Db $cachedNew $variantDb
$code = Invoke-Idat (Join-Path $PSScriptRoot 'make_fixture.py') $variantDb 'variant-fixture' '--new-variant'
if ($code -ne 0 -or (Test-Path -LiteralPath ($fixture + '.error.txt'))) { Stop-Run "make_fixture.py --new-variant exit $code, see $Scratch\variant-fixture.ida.log" }

$hashOld = Hash $annotated
$hashNew = Hash $cachedNew
$hashCachedOld = Hash $cachedOld

Step 'port-ida-database'
$result = Join-Path $Scratch 'result.i64'
$portSw = [System.Diagnostics.Stopwatch]::StartNew()
$run = Run-Launcher 'port' @('-OldDb', $annotated, '-OutDir', $out, '-Output', $result, '-Force', '-IdaDir', $ida)
$portSeconds = $portSw.Elapsed.TotalSeconds
if ($run.code -ne 0) { Stop-Run "the launcher exit $($run.code)" }
$mainDump = Join-Path $Scratch 'port-ida-database.dump.json'
$passTimes = @([regex]::Matches($run.text, '(?m)^\s*(baseline|export|apply) in (\d+) s') | ForEach-Object { "$($_.Groups[1].Value) $($_.Groups[2].Value) s" })
$metrics = "main dump: {0} bytes; launcher {1:0} s ({2})" -f (Get-Item -LiteralPath $mainDump).Length, $portSeconds, ($passTimes -join ', ')
Write-Host "   $metrics"
[System.IO.File]::WriteAllText((Join-Path $Scratch 'metrics.txt'), $metrics + "`r`n", $utf8)
$dumpText = [System.IO.File]::ReadAllText($mainDump, $utf8)
Add-Check 'dump-one-line' ($dumpText.Trim() -notmatch "`n") 'the dump is written with line breaks, not as compact JSON'
Add-Check 'report-written' ((Test-Path -LiteralPath (Join-Path $Scratch 'port-ida-database.log')) -and (Test-Path -LiteralPath (Join-Path $Scratch 'port-ida-database.dump.json'))) 'no port-ida-database.log or dump beside result.i64'
Add-Check 'no-temp-left' (-not (Test-Path -LiteralPath (Join-Path $Scratch '.port-ida-database.tmp')) -and -not (Test-Path -LiteralPath ($result + '.partial'))) 'the launcher left its temp folder or .partial file'
Add-Check 'console-summary' ($run.text -match '\d+ ported, \d+ listed for review, \d+ warnings?, mismatches not checked') 'the console has no summary line with the four counts'

Step 'locked output: -Force onto a file held open must fail and leave it alone'
$locked = Join-Path $Scratch 'locked\result.i64'
if (Test-Path -LiteralPath (Split-Path $locked -Parent)) { Remove-Item -LiteralPath (Split-Path $locked -Parent) -Recurse -Force }
[void](New-Item -ItemType Directory -Path (Split-Path $locked -Parent))
[System.IO.File]::WriteAllText($locked, 'previous output', $utf8)
$hashLocked = Hash $locked
$hold = [System.IO.File]::Open($locked, 'Open', 'ReadWrite', 'None')
try {
	$run = Run-Launcher 'locked' @('-OldDb', $annotated, '-OutDir', $out, '-Output', $locked, '-Force', '-IdaDir', $ida)
} finally {
	$hold.Dispose()
}
$why = @()
if ($run.code -ne 2) { $why += "exit $($run.code), expected 2" }
if ($run.text -match 'written:') { $why += 'it says written' }
if ($run.text -notmatch 'cannot write') { $why += 'no "cannot write" message' }
if (Test-Path -LiteralPath ($locked + '.partial')) { $why += '.partial left behind' }
if (Test-Path -LiteralPath (Join-Path (Split-Path $locked -Parent) '.port-ida-database.tmp')) { $why += 'temp folder left behind' }
if ((Hash $locked) -ne $hashLocked) { $why += 'the held output changed' }
Add-Check 'locked-output' ($why.Count -eq 0) ($why -join ', ')
Remove-Item -LiteralPath (Split-Path $locked -Parent) -Recurse -Force

Step 'check the output'
$env:EXEDFIX_CHECK = $checkFile
$env:EXEDFIX_COUNT = Join-Path $Scratch 'new_count.txt'
$env:EXEDFIX_MODE = 'count'
$countCopy = Join-Path $Scratch 'count_copy.i64'
Copy-Db $cachedNew $countCopy
$code = Invoke-Idat (Join-Path $PSScriptRoot 'check_output.py') $countCopy 'count'
Remove-Item -LiteralPath $countCopy -Force
if ($code -ne 0) { Stop-Run "check_output.py (count) exit $code" }
$env:EXEDFIX_SNAPSHOT = Join-Path $Scratch 'snapshot.json'
if (Test-Path -LiteralPath $env:EXEDFIX_SNAPSHOT) { Remove-Item -LiteralPath $env:EXEDFIX_SNAPSHOT }
function Check-Db($mode, $db, $log) {
	$env:EXEDFIX_MODE = $mode
	$env:EXEDFIX_LOG = $log
	$env:EXEDFIX_DUMP = [System.IO.Path]::ChangeExtension($log, '.dump.json')
	$copy = Join-Path $Scratch "result_$mode.i64"
	Copy-Db $db $copy
	$code = Invoke-Idat (Join-Path $PSScriptRoot 'check_output.py') $copy $mode
	Remove-Item -LiteralPath $copy -Force
	if ($code -ne 0) { Add-Check "check_output $mode" $false "idat exit $code" }
}
Check-Db 'check' $result (Join-Path $Scratch 'port-ida-database.log')

Step 'apply again: the launcher on its own output must change nothing'
$hashResult = Hash $result
$again = Join-Path $Scratch 'again\result.i64'
$run = Run-Launcher 'again' @('-OldDb', $annotated, '-OutDir', $out, '-NewDb', $result, '-Output', $again, '-Force', '-IdaDir', $ida)
if ($run.code -ne 0) { Add-Check 'again-launcher' $false "exit $($run.code)" }
else { Check-Db 'again' $again (Join-Path $Scratch 'again\port-ida-database.log') }
Add-Check 'again-input-unchanged' ((Hash $result) -eq $hashResult) 'result.i64 changed when given as -NewDb'

Step 'variant: a name already in use and a paired address that is not a function'
$variant = Join-Path $Scratch 'variant\result.i64'
$run = Run-Launcher 'variant' @('-OldDb', $annotated, '-OutDir', $out, '-NewDb', $variantDb, '-Output', $variant, '-Force', '-IdaDir', $ida)
if ($run.code -ne 0) { Add-Check 'variant-launcher' $false "exit $($run.code)" }
else { Check-Db 'variant' $variant (Join-Path $Scratch 'variant\port-ida-database.log') }

Step 'no analysis cache: the launcher warns and still ports'
$nobaseOut = Join-Path $Scratch 'nobase-out'
if (Test-Path -LiteralPath $nobaseOut) { Remove-Item -LiteralPath $nobaseOut -Recurse -Force }
[void](New-Item -ItemType Directory -Path $nobaseOut)
Copy-Item -LiteralPath (Join-Path $out 'map.csv') -Destination $nobaseOut
$pairText = [System.IO.File]::ReadAllText((Join-Path $out 'pair.txt'), $utf8) -replace '(?m)^old_work=.*$', ('old_work=' + (Join-Path $nobaseOut 'no-work'))
[System.IO.File]::WriteAllText((Join-Path $nobaseOut 'pair.txt'), $pairText, $utf8)
$nobase = Join-Path $Scratch 'nobase\result.i64'
$run = Run-Launcher 'nobase' @('-OldDb', $annotated, '-OutDir', $nobaseOut, '-Output', $nobase, '-Force', '-IdaDir', $ida)
$nobaseLog = Join-Path $Scratch 'nobase\port-ida-database.log'
$why = @()
if ($run.code -ne 0) { $why += "exit $($run.code)" }
if (-not (Test-Path -LiteralPath $nobase)) { $why += 'no output' }
if (-not (Test-Path -LiteralPath $nobaseLog) -or (Get-Content -LiteralPath $nobaseLog -Raw) -notmatch 'no analysis cache for Trove_x64\.old\.exe') { $why += 'no warning in the log' }
Add-Check 'no-baseline-warns' ($why.Count -eq 0) ($why -join ', ')
$why = @()
$nobaseDump = Join-Path $Scratch 'nobase\port-ida-database.dump.json'
if (-not (Test-Path -LiteralPath $nobaseDump)) { $why += 'no dump' }
else {
	Write-Host ("   no-cache dump: {0} bytes" -f (Get-Item -LiteralPath $nobaseDump).Length)
	$nobaseFuncs = ([System.IO.File]::ReadAllText($nobaseDump, $utf8) | ConvertFrom-Json).functions
	foreach ($f in $nobaseFuncs.PSObject.Properties) {
		$names = @($f.Value.PSObject.Properties.Name)
		if ($names -contains 'insn') { $why += "$($f.Name) has instruction items" }
		if ($names -contains 'shape' -and $names -notcontains 'hexrays') { $why += "$($f.Name) has a shape but no Hex-Rays data" }
	}
}
$logText = if (Test-Path -LiteralPath $nobaseLog) { [System.IO.File]::ReadAllText($nobaseLog, $utf8) } else { '' }
$warned = ([regex]::Matches($logText, 'no baseline: instruction comments and operand formats are not ported')).Count
if ($warned -ne 1) { $why += "the instruction warning is in the log $warned time(s)" }
$summary = ($logText -split "`r?`n`r?`nWarnings")[0]
foreach ($kind in 'function names', 'local types') { if ($summary -notmatch "(?m)^ +${kind}: [1-9]") { $why += "nothing counted as $kind" } }
if ($summary -match '(?m)^ +(instruction comments|operand formats):') { $why += 'instruction data was ported' }
$insnLines = 0
$category = ''
foreach ($line in ($logText.Substring([Math]::Max(0, $logText.IndexOf('Needs review'))) -split "`r?`n")) {
	if ($line -match '^    ' -and $line -notmatch '^    note: ') { if ($category -like 'insn-*') { $insnLines++ } }
	elseif ($line -match '^  (\S+) \(\d+\)$') { $category = $Matches[1] }
}
if ($insnLines -ge 50) { $why += "$insnLines insn-* review lines" }
Add-Check 'no-baseline-no-insn' ($why.Count -eq 0) ($why -join ', ')
$why = @()
if (Test-Path -LiteralPath $nobaseDump) {
	$nobaseJson = [System.IO.File]::ReadAllText($nobaseDump, $utf8)
	if ($nobaseJson -match '"proto"\s*:') { $why += 'the dump has prototypes' }
	if ($nobaseJson -notmatch '"data"\s*:\s*\[\s*\]') { $why += 'the dump has data items' }
} else { $why += 'no dump' }
foreach ($w in 'no baseline: function prototypes are not ported', 'no baseline: data names, comments and types are not ported') {
	$n = ([regex]::Matches($logText, [regex]::Escape($w))).Count
	if ($n -ne 1) { $why += "'$w' is in the log $n time(s)" }
}
if ($summary -match '(?m)^ +(function prototypes|data names|data comments|data types):') { $why += 'prototypes or data were ported' }
$why3 = @()
foreach ($w in 'no baseline: instruction comments and operand formats are not ported', 'no baseline: function prototypes are not ported') {
	if ($run.text -notmatch [regex]::Escape($w)) { $why3 += "the console does not show '$w'" }
}
Add-Check 'console-warning-lines' ($why3.Count -eq 0) ($why3 -join ', ')
$why2 = @()
$fixtureJson = [System.IO.File]::ReadAllText($fixture, $utf8) | ConvertFrom-Json
$hexWant = @($fixtureJson.hexrays | Where-Object { $_.expect -eq 'ported' } | ForEach-Object { [string]$_.old_ea })
$hexHave = @()
if ($nobaseFuncs) { $hexHave = @($nobaseFuncs.PSObject.Properties | Where-Object { @($_.Value.PSObject.Properties.Name) -contains 'hexrays' } | ForEach-Object { $_.Name }) }
$hexHaveText = (@($hexHave | Sort-Object) -join ',')
$hexWantText = (@($hexWant | Sort-Object) -join ',')
if (-not $hexWantText -or $hexHaveText -ne $hexWantText) { $why2 += "the dump has Hex-Rays data for '$hexHaveText', want '$hexWantText'" }
foreach ($kind in 'Hex-Rays comments', 'Hex-Rays variable settings') { if ($summary -notmatch "(?m)^ +${kind}: [1-9]") { $why2 += "nothing counted as $kind" } }
if ($logText -match 'Hex-Rays[^\r\n]*(baseline|cannot be told)') { $why2 += 'the log says Hex-Rays data needs a baseline' }
Add-Check 'no-baseline-hexrays' ($why2.Count -eq 0) ($why2 -join ', ')
$dataLines = 0
$category = ''
foreach ($line in ($logText.Substring([Math]::Max(0, $logText.IndexOf('Needs review'))) -split "`r?`n")) {
	if ($line -match '^    ' -and $line -notmatch '^    note: ') { if ($category -like 'proto-*' -or $category -like 'data-*') { $dataLines++ } }
	elseif ($line -match '^  (\S+) \(\d+\)$') { $category = $Matches[1] }
}
if ($dataLines -gt 0) { $why += "$dataLines proto-*/data-* review lines" }
Add-Check 'no-baseline-no-protos-data' ($why.Count -eq 0) ($why -join ', ')
$withLog = Get-Content -LiteralPath (Join-Path $Scratch 'port-ida-database.log') -Raw
Add-Check 'baseline-used' ($withLog -notmatch 'no analysis cache') 'the main run logged that it had no analysis cache'
$why = @()
foreach ($t in 'rebased', 'could not be checked') { if ($withLog -match $t) { $why += "the main log says '$t'" } }
if ($logText -match 'rebased|could not be checked') { $why += 'the no-cache log says the image base could not be checked or was rebased' }
Add-Check 'imagebase-unaffected' ($why.Count -eq 0) ($why -join ', ')

Step 'verify: -Verify decompiles the functions with Hex-Rays data or a prototype on both sides'
$verifyOut = Join-Path $Scratch 'verify\result.i64'
$run = Run-Launcher 'verify' @('-OldDb', $annotated, '-OutDir', $out, '-Output', $verifyOut, '-Force', '-Verify', '-IdaDir', $ida)
$why = @()
if ($run.code -ne 0) { $why += "exit $($run.code)" }
if (-not (Test-Path -LiteralPath $verifyOut)) { $why += 'no output' }
if ($run.text -match 'not available yet') { $why += 'the launcher says -Verify is not available' }
if ($run.text -notmatch '\d+ ported, \d+ listed for review, \d+ warnings?, \d+ mismatch') { $why += 'the console has no summary line with a mismatch count' }
if (Test-Path -LiteralPath (Join-Path $Scratch 'verify\.port-ida-database.tmp')) { $why += 'temp folder left behind' }
Add-Check 'verify-launcher' ($why.Count -eq 0) ($why -join ', ')
if (Test-Path -LiteralPath $verifyOut) { Check-Db 'verify' $verifyOut (Join-Path $Scratch 'verify\port-ida-database.log') }

Step 'empty: an old database with no annotations of the owner'
$emptyDb = Join-Path $Scratch 'old_empty.i64'
Copy-Db $cachedOld $emptyDb
$code = Invoke-Idat (Join-Path $PSScriptRoot 'make_fixture.py') $emptyDb 'empty-fixture' '--empty'
if ($code -ne 0 -or (Test-Path -LiteralPath ($fixture + '.error.txt'))) { Stop-Run "make_fixture.py --empty exit $code, see $Scratch\empty-fixture.ida.log" }
$emptyOut = Join-Path $Scratch 'empty\result.i64'
$run = Run-Launcher 'empty' @('-OldDb', $emptyDb, '-OutDir', $out, '-Output', $emptyOut, '-Force', '-IdaDir', $ida)
$why = @()
if ($run.code -ne 0) { $why += "exit $($run.code)" }
if (-not (Test-Path -LiteralPath $emptyOut)) { $why += 'no output' }
if ($run.text -notmatch '(?m)\b0 ported') { $why += 'the console does not say 0 ported' }
if ($run.text -notmatch 'no annotations of yours') { $why += 'the console does not say that the old database has no annotations' }
Add-Check 'empty-launcher' ($why.Count -eq 0) ($why -join ', ')
if (Test-Path -LiteralPath $emptyOut) { Check-Db 'empty' $emptyOut (Join-Path $Scratch 'empty\port-ida-database.log') }

Step 'type library: the old database loads one the new database does not'
$tilDb = Join-Path $Scratch 'old_til.i64'
Copy-Db $emptyDb $tilDb
$code = Invoke-Idat (Join-Path $PSScriptRoot 'make_fixture.py') $tilDb 'til-fixture' '--add-til'
if ($code -ne 0 -or (Test-Path -LiteralPath ($fixture + '.error.txt'))) { Stop-Run "make_fixture.py --add-til exit $code, see $Scratch\til-fixture.ida.log" }
$hashTil = Hash $tilDb
$tilOut = Join-Path $Scratch 'til\result.i64'
$run = Run-Launcher 'til' @('-OldDb', $tilDb, '-OutDir', $out, '-Output', $tilOut, '-Force', '-IdaDir', $ida)
$tilLog = Join-Path $Scratch 'til\port-ida-database.log'
$why = @()
if ($run.code -ne 0) { $why += "exit $($run.code)" }
if (-not (Test-Path -LiteralPath $tilOut)) { $why += 'no output' }
if ($run.text -notmatch 'ntddk64_win10') { $why += 'the console does not name ntddk64_win10' }
$tilText = if (Test-Path -LiteralPath $tilLog) { [System.IO.File]::ReadAllText($tilLog, $utf8) } else { '' }
$tilWarnings = @((($tilText -split "`r?`nWarnings`r?`n", 2)[-1] -split "`r?`n`r?`nNeeds review")[0] -split "`r?`n" | Where-Object { $_.Trim() })
if ($tilText -notmatch "`nWarnings") { $why += 'the log has no Warnings section' }
elseif ($tilWarnings.Count -eq 0 -or $tilWarnings[0] -notmatch 'type librar' -or $tilWarnings[0] -notmatch 'ntddk64_win10') { $why += "the first warning is '$($tilWarnings | Select-Object -First 1)'" }
if ($tilText -notmatch '(?m)^  warnings: [1-9]') { $why += 'the Summary counts no warning' }
Add-Check 'context-warns' ($why.Count -eq 0) ($why -join ', ')
$strictDir = Join-Path $Scratch 'til-strict'
if (Test-Path -LiteralPath $strictDir) { Remove-Item -LiteralPath $strictDir -Recurse -Force }
$strictOut = Join-Path $strictDir 'result.i64'
$run = Run-Launcher 'til-strict' @('-OldDb', $tilDb, '-OutDir', $out, '-Output', $strictOut, '-Strict', '-IdaDir', $ida)
$why = @()
if ($run.code -ne 1) { $why += "exit $($run.code), expected 1" }
if (Test-Path -LiteralPath $strictOut) { $why += 'the output was written' }
if (Test-Path -LiteralPath ($strictOut + '.partial')) { $why += '.partial left behind' }
if (Test-Path -LiteralPath (Join-Path $strictDir '.port-ida-database.tmp')) { $why += 'temp folder left behind' }
if ($run.text -match 'written:') { $why += 'it says written' }
if ($run.text -notmatch 'ntddk64_win10') { $why += 'the console does not name ntddk64_win10' }
Add-Check 'context-strict' ($why.Count -eq 0) ($why -join ', ')
Add-Check 'til-db-unchanged' ((Hash $tilDb) -eq $hashTil) 'old_til.i64 changed'

Step 'md5 refusal: the new database given as the old one'
$wrong = Join-Path $Scratch 'wrong_old.i64'
Copy-Db $cachedNew $wrong
$hashWrong = Hash $wrong
$refusedDir = Join-Path $Scratch 'refused'
if (Test-Path -LiteralPath $refusedDir) { Remove-Item -LiteralPath $refusedDir -Recurse -Force }
$run = Run-Launcher 'refused' @('-OldDb', $wrong, '-OutDir', $out, '-Output', (Join-Path $refusedDir 'result.i64'), '-Force', '-IdaDir', $ida)
$written = @(Get-ChildItem -LiteralPath $refusedDir -Recurse -Force -ErrorAction SilentlyContinue)
$why = @()
if ($run.code -ne 1) { $why += "exit $($run.code)" }
if ($run.text -notmatch 'not for') { $why += 'no "not for" message' }
if ($written.Count -gt 0) { $why += "$($written.Count) file(s) written" }
if ((Hash $wrong) -ne $hashWrong) { $why += 'the database given as -OldDb changed' }
Add-Check 'md5-refusal' ($why.Count -eq 0) ($why -join ', ')
Remove-Item -LiteralPath $wrong -Force

function Rebased-Copy($from, $name) {
	$db = Join-Path $Scratch "$name.i64"
	Copy-Db $from $db
	$code = Invoke-Idat (Join-Path $PSScriptRoot 'make_fixture.py') $db "$name-fixture" '--rebase'
	if ($code -ne 0 -or (Test-Path -LiteralPath ($fixture + '.error.txt'))) { Stop-Run "make_fixture.py --rebase exit $code, see $Scratch\$name-fixture.ida.log" }
	return $db
}
function Rebase-Checks($run, $dir, $which) {
	$result = Join-Path $dir 'result.i64'
	$why = @()
	if ($run.code -ne 1) { $why += "exit $($run.code), expected 1" }
	if ($run.text -match 'written:') { $why += 'it says written' }
	$m = [regex]::Match($run.text, "$which database was rebased from 0x([0-9A-F]+) to 0x([0-9A-F]+)")
	if (-not $m.Success) { $why += "no '$which database was rebased from ... to ...' message" }
	elseif ([Convert]::ToInt64($m.Groups[2].Value, 16) - [Convert]::ToInt64($m.Groups[1].Value, 16) -ne 0x10000) { $why += "the message names 0x$($m.Groups[1].Value) and 0x$($m.Groups[2].Value)" }
	if ($run.text -notmatch 'rebase it back') { $why += "no 'rebase it back' advice" }
	if (Test-Path -LiteralPath $result) { $why += 'the output was written' }
	if (Test-Path -LiteralPath ($result + '.partial')) { $why += '.partial left behind' }
	if (Test-Path -LiteralPath (Join-Path $dir '.port-ida-database.tmp')) { $why += 'temp folder left behind' }
	return $why
}

Step 'rebased old database: a copy rebased by 0x10000 must be refused without -Strict'
$rebasedOld = Rebased-Copy $annotated 'old_rebased'
$hashRebased = Hash $rebasedOld
$rebasedDir = Join-Path $Scratch 'rebased-old'
if (Test-Path -LiteralPath $rebasedDir) { Remove-Item -LiteralPath $rebasedDir -Recurse -Force }
$run = Run-Launcher 'rebased-old' @('-OldDb', $rebasedOld, '-OutDir', $out, '-Output', (Join-Path $rebasedDir 'result.i64'), '-Force', '-IdaDir', $ida)
$why = Rebase-Checks $run $rebasedDir 'old'
$written = @(Get-ChildItem -LiteralPath $rebasedDir -Recurse -Force -ErrorAction SilentlyContinue)
if ($written.Count -gt 0) { $why += "$($written.Count) file(s) written: $(($written | ForEach-Object { $_.Name }) -join ', ')" }
if ((Hash $rebasedOld) -ne $hashRebased) { $why += 'the rebased old database changed' }
Add-Check 'rebased-old-refused' ($why.Count -eq 0) ($why -join ', ')
Remove-Item -LiteralPath $rebasedOld -Force

Step 'rebased new database: a copy of the new analysis rebased by 0x10000 given as -NewDb must be refused'
$rebasedNew = Rebased-Copy $cachedNew 'new_rebased'
$hashRebased = Hash $rebasedNew
$rebasedDir = Join-Path $Scratch 'rebased-new'
if (Test-Path -LiteralPath $rebasedDir) { Remove-Item -LiteralPath $rebasedDir -Recurse -Force }
$run = Run-Launcher 'rebased-new' @('-OldDb', $annotated, '-OutDir', $out, '-NewDb', $rebasedNew, '-Output', (Join-Path $rebasedDir 'result.i64'), '-Force', '-IdaDir', $ida)
$why = Rebase-Checks $run $rebasedDir 'new'
$left = @(Get-ChildItem -LiteralPath $rebasedDir -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'port-ida-database.log', 'port-ida-database.dump.json' })
if ($left.Count -gt 0) { $why += "left behind: $(($left | ForEach-Object { $_.Name }) -join ', ')" }
if ((Hash $rebasedNew) -ne $hashRebased) { $why += 'the rebased new database changed' }
Add-Check 'rebased-new-refused' ($why.Count -eq 0) ($why -join ', ')
Remove-Item -LiteralPath $rebasedNew -Force

Step 'unchecked new image base: pair.txt names no readable new exe and -NewDb is given'
$uncheckedOut = Join-Path $Scratch 'unchecked-out'
if (Test-Path -LiteralPath $uncheckedOut) { Remove-Item -LiteralPath $uncheckedOut -Recurse -Force }
[void](New-Item -ItemType Directory -Path $uncheckedOut)
Copy-Item -LiteralPath (Join-Path $out 'map.csv') -Destination $uncheckedOut
$pairText = [System.IO.File]::ReadAllText((Join-Path $out 'pair.txt'), $utf8)
$pairText = $pairText -replace '(?m)^new_work=.*$', ('new_work=' + (Join-Path $uncheckedOut 'no-work')) -replace '(?m)^new_exe=.*$', ('new_exe=' + (Join-Path $uncheckedOut 'no-such.exe'))
[System.IO.File]::WriteAllText((Join-Path $uncheckedOut 'pair.txt'), $pairText, $utf8)
$uncheckedDb = Join-Path $Scratch 'new_unchecked.i64'
Copy-Db $cachedNew $uncheckedDb
$hashUnchecked = Hash $uncheckedDb
$uncheckedDir = Join-Path $Scratch 'unchecked'
if (Test-Path -LiteralPath $uncheckedDir) { Remove-Item -LiteralPath $uncheckedDir -Recurse -Force }
$run = Run-Launcher 'unchecked' @('-OldDb', $annotated, '-OutDir', $uncheckedOut, '-NewDb', $uncheckedDb, '-Output', (Join-Path $uncheckedDir 'result.i64'), '-Force', '-IdaDir', $ida)
$why = @()
if ($run.code -ne 1) { $why += "exit $($run.code), expected 1" }
if ($run.text -match 'written:') { $why += 'it says written' }
if ($run.text -notmatch 'could not be checked') { $why += "no 'could not be checked' message" }
if ($run.text -notmatch '-NewDb was given') { $why += "no '-NewDb was given' reason" }
if (Test-Path -LiteralPath (Join-Path $uncheckedDir 'result.i64')) { $why += 'the output was written' }
if (Test-Path -LiteralPath (Join-Path $uncheckedDir '.port-ida-database.tmp')) { $why += 'temp folder left behind' }
if ((Hash $uncheckedDb) -ne $hashUnchecked) { $why += 'the database given as -NewDb changed' }
Add-Check 'unchecked-newdb-refused' ($why.Count -eq 0) ($why -join ', ')
Remove-Item -LiteralPath $uncheckedDb -Force

Step 'seam: apply_db.py on a copy with a dump edited to hold a type IDA reads back differently and an unresolvable type name'
$python = Get-Command python -ErrorAction SilentlyContinue
$seamDir = Join-Path $Scratch 'seam'
if (Test-Path -LiteralPath $seamDir) { Remove-Item -LiteralPath $seamDir -Recurse -Force }
[void](New-Item -ItemType Directory -Path $seamDir)
$why = @()
if (-not $python) { $why += 'python is not on PATH' }
else {
	$seamDump = Join-Path $seamDir 'seam.dump.json'
	& $python.Source -I (Join-Path $PSScriptRoot 'seam_dump.py') $mainDump $seamDump
	if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $seamDump)) { $why += "seam_dump.py exit $LASTEXITCODE" }
	else {
		$seamDb = Join-Path $seamDir 'seam.i64'
		Copy-Db $cachedNew $seamDb
		$seamLog = Join-Path $seamDir 'seam.log'
		$saved = @{}
		$seamEnv = @{ PORTDB_DUMP = $seamDump; PORTDB_PAIR = (Join-Path $out 'pair.txt'); PORTDB_MAP = (Join-Path $out 'map.csv'); PORTDB_LOG = $seamLog
			PORTDB_RESULT = (Join-Path $seamDir 'apply.result.txt'); PORTDB_STATE = (Join-Path $seamDir 'state.json'); PORTDB_SUMMARY = (Join-Path $seamDir 'summary.txt')
			PORTDB_MIN_SIMILARITY = '80'; PORTDB_INCLUDE_LIKELY = '0'; PORTDB_VERIFY = '0'; PORTDB_STRICT = '0'; PORTDB_NEWDB_GIVEN = '0'
			PORTDB_OLD_EXE_NAME = 'Trove_x64.old.exe'; PORTDB_BASELINE = ''; PORTDB_BASELINE_WARNING = '' }
		foreach ($k in $seamEnv.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, $seamEnv[$k]) }
		try { $code = Invoke-Idat (Join-Path $project 'scripts\port-ida-database\apply_db.py') $seamDb 'seam' }
		finally { foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) } }
		$seamResult = if (Test-Path -LiteralPath $seamEnv.PORTDB_RESULT) { [System.IO.File]::ReadAllText($seamEnv.PORTDB_RESULT, $utf8) } else { '' }
		if ($code -ne 0 -or -not $seamResult.StartsWith('ok')) { $why += "apply_db.py exit $code, result '$($seamResult.Trim())'" }
		$seamText = if (Test-Path -LiteralPath $seamLog) { [System.IO.File]::ReadAllText($seamLog, $utf8) } else { '' }
		if ($seamText -notmatch '(?m)^    ExedFixSeam: IDA reads its declaration differently in the new database \([^\r\n]*\); removed again') { $why += 'no type-failed entry saying ExedFixSeam was read differently and removed again' }
		if ($seamText -notmatch '(?m)^    ExedFix_Data_Plain: its type int is not ported: the type ExedFix<Odd> cannot be checked against the new database: its name is not a plain C name') { $why += 'no data-skipped entry for the unresolvable type name' }
		foreach ($ext in '.i64', '.id0', '.id1', '.id2', '.nam', '.til') {
			$p = [System.IO.Path]::ChangeExtension($seamDb, $ext)
			if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
		}
	}
}
Add-Check 'seam-type-roundtrip-and-odd-name' ($why.Count -eq 0) ($why -join ', ')

Step 'the inputs are untouched'
Add-Check 'old-db-unchanged' ((Hash $annotated) -eq $hashOld) 'old_annotated.i64 changed'
Add-Check 'cached-new-db-unchanged' ((Hash $cachedNew) -eq $hashNew) "$cachedNew changed"
Add-Check 'cached-old-db-unchanged' ((Hash $cachedOld) -eq $hashCachedOld) "$cachedOld changed"

$lines = @(Get-Content -LiteralPath $checkFile)
foreach ($l in $lines) { Write-Host $l -ForegroundColor $(if ($l -like 'CHECK ok*') { 'Green' } else { 'Red' }) }
$bad = @($lines | Where-Object { $_ -notlike 'CHECK ok*' })
if (-not ($lines -contains 'CHECK ok output-opens')) { $bad += 'output-opens missing' }
Write-Host ("{0} checks, {1} failed, {2:0} s" -f $lines.Count, $bad.Count, $sw.Elapsed.TotalSeconds)
if ($bad.Count -gt 0) { exit 1 }
exit 0
