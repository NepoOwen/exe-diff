param(
	[string]$Launcher = (Join-Path $PSScriptRoot '..\..\scripts\port-ida-database\port-ida-database.ps1'),
	[string]$Scratch = (Join-Path $env:TEMP 'port-ida-database-checks')
)

$Launcher = [System.IO.Path]::GetFullPath($Launcher)
$Scratch = [System.IO.Path]::GetFullPath($Scratch).TrimEnd('\')
$marker = '.launcher-checks-scratch'
function Inside($path, $folder) {
	$p = $path.TrimEnd('\') + '\'
	$f = ([System.IO.Path]::GetFullPath($folder)).TrimEnd('\') + '\'
	return $f.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)
}
$why = ''
if ([System.IO.Path]::GetPathRoot($Scratch).TrimEnd('\') -ieq $Scratch) { $why = 'it is a drive root' }
elseif (Inside $Scratch (Join-Path $PSScriptRoot '..\..')) { $why = 'it holds the project' }
elseif ($env:USERPROFILE -and (Inside $Scratch $env:USERPROFILE)) { $why = 'it holds the user profile' }
elseif ((Split-Path $Scratch -Leaf) -notmatch '(?i)check|scratch|te?mp') { $why = "its name does not look like a scratch folder (it must contain 'check', 'scratch', 'tmp' or 'temp')" }
elseif ((Test-Path -LiteralPath $Scratch) -and @(Get-ChildItem -LiteralPath $Scratch -Force).Count -gt 0 -and -not (Test-Path -LiteralPath (Join-Path $Scratch $marker))) { $why = 'it is not empty and was not made by this script' }
if ($why) { Write-Host "refused -Scratch ${Scratch}: $why" -ForegroundColor Red; exit 2 }
if (Test-Path -LiteralPath $Scratch) { Remove-Item -LiteralPath $Scratch -Recurse -Force }
[void](New-Item -ItemType Directory -Path $Scratch)
[System.IO.File]::WriteAllText((Join-Path $Scratch $marker), '')

$utf8 = New-Object System.Text.UTF8Encoding($false)
function Put($path, $text) {
	$parent = Split-Path $path -Parent
	if (-not (Test-Path -LiteralPath $parent)) { [void](New-Item -ItemType Directory -Path $parent -Force) }
	[System.IO.File]::WriteAllText($path, $text, $utf8)
}

$newHeader = "status,name,old_va,new_va,old_size,new_size,method,similarity`n" + "same,sub_140001010,0x140001010,0x140001010,75,75,exact-unique,100`n"
$oldHeader = "status,name,old_va,new_va,old_size,new_size`n" + "same,sub_140001010,0x140001010,0x140001010,75,75`n"
$newWork = Join-Path $Scratch 'work\new'
Put (Join-Path $newWork 'input.exe.i64') 'fake new db'
function Pair($oldMd5) {
	return "old_exe=C:\x\Trove_x64.old.exe`nold_size=1`nold_md5=$oldMd5`nold_work=C:\x\work\old`n" +
		"new_exe=C:\x\Trove_x64.new.exe`nnew_size=1`nnew_md5=00112233445566778899aabbccddeeff`nnew_work=$newWork`n"
}
$pairOk = Pair 'ffeeddccbbaa99887766554433221100'

$ok = Join-Path $Scratch 'out-ok'
Put (Join-Path $ok 'map.csv') $newHeader
Put (Join-Path $ok 'pair.txt') $pairOk
$noMap = Join-Path $Scratch 'out-nomap'
Put (Join-Path $noMap 'pair.txt') $pairOk
$noPair = Join-Path $Scratch 'out-nopair'
Put (Join-Path $noPair 'map.csv') $newHeader
$oldMap = Join-Path $Scratch 'out-oldmap'
Put (Join-Path $oldMap 'map.csv') $oldHeader
Put (Join-Path $oldMap 'pair.txt') $pairOk
$noMd5 = Join-Path $Scratch 'out-nomd5'
Put (Join-Path $noMd5 'map.csv') $newHeader
Put (Join-Path $noMd5 'pair.txt') (Pair '')

$db = Join-Path $Scratch 'dbs\annotated.i64'
Put $db 'fake old db'
$openDb = Join-Path $Scratch 'dbs\open.i64'
Put $openDb 'fake open db'
Put (Join-Path $Scratch 'dbs\open.id0') 'unpacked'
$exists = Join-Path $Scratch 'result\exists.i64'
Put $exists 'already here'
$fresh = Join-Path $Scratch 'result\fresh.i64'
$hardLink = Join-Path $Scratch 'result\hardlink.i64'
[void](New-Item -ItemType HardLink -Path $hardLink -Target $db)
$junction = Join-Path $Scratch 'junction'
[void](New-Item -ItemType Junction -Path $junction -Target (Join-Path $Scratch 'dbs'))
$openOut = Join-Path $Scratch 'result\openout.i64'
Put $openOut 'previous output'
Put (Join-Path $Scratch 'result\openout.id0') 'unpacked'
$noIda = Join-Path $Scratch 'not-ida'
[void](New-Item -ItemType Directory -Path $noIda -Force)

$cases = @(
	@{ name = 'missing -OldDb'; args = @(); want = 'usage' },
	@{ name = '-OldDb not found'; args = @((Join-Path $Scratch 'dbs\missing.i64'), '-OutDir', $ok, '-Output', $fresh, '-IdaDir', $noIda); want = 'not found' },
	@{ name = 'unpacked .id0 beside the db'; args = @($openDb, '-OutDir', $ok, '-Output', $fresh, '-IdaDir', $noIda); want = 'open in IDA' },
	@{ name = '-OutDir without map.csv'; args = @($db, '-OutDir', $noMap, '-Output', $fresh, '-IdaDir', $noIda); want = 'map\.csv' },
	@{ name = '-OutDir without pair.txt'; args = @($db, '-OutDir', $noPair, '-Output', $fresh, '-IdaDir', $noIda); want = 'pair\.txt' },
	@{ name = 'map.csv with the old 6-column header'; args = @($db, '-OutDir', $oldMap, '-Output', $fresh, '-IdaDir', $noIda); want = 'older exediff' },
	@{ name = 'pair.txt without old_md5'; args = @($db, '-OutDir', $noMd5, '-Output', $fresh, '-IdaDir', $noIda); want = 'old_md5' },
	@{ name = '-MinSimilarity out of range'; args = @($db, '-OutDir', $ok, '-Output', $fresh, '-MinSimilarity', '150', '-IdaDir', $noIda); want = 'MinSimilarity' },
	@{ name = 'output exists without -Force'; args = @($db, '-OutDir', $ok, '-Output', $exists, '-IdaDir', $noIda); want = '-Force' },
	@{ name = '-Output is the old database'; args = @($db, '-OutDir', $ok, '-Output', $db, '-Force', '-IdaDir', $noIda); want = 'overwrite' },
	@{ name = '-Output is a hard link to the old database'; args = @($db, '-OutDir', $ok, '-Output', $hardLink, '-Force', '-IdaDir', $noIda); want = 'overwrite' },
	@{ name = '-Output reaches the old database through a junction'; args = @($db, '-OutDir', $ok, '-Output', (Join-Path $junction 'annotated.i64'), '-Force', '-IdaDir', $noIda); want = 'overwrite' },
	@{ name = '-Output looks open in IDA'; args = @($db, '-OutDir', $ok, '-Output', $openOut, '-Force', '-IdaDir', $noIda); want = 'output looks open in IDA' },
	@{ name = 'bad -IdaDir'; args = @($db, '-OutDir', $ok, '-Output', $fresh, '-IdaDir', $noIda); want = 'idat\.exe' },
	@{ name = '-Strict without the analysis cache of the old exe'; args = @($db, '-OutDir', $ok, '-Output', $fresh, '-Strict', '-IdaDir', $noIda); want = 'no analysis cache for Trove_x64\.old\.exe' }
)

$failed = 0
foreach ($c in $cases) {
	$a = $c.args
	$text = (& powershell -NoProfile -ExecutionPolicy Bypass -File $Launcher @a 2>&1 | Out-String)
	$code = $LASTEXITCODE
	$why = @()
	if ($code -ne 1) { $why += "exit $code, expected 1" }
	if ($text -notmatch $c.want) { $why += "output does not match '$($c.want)'" }
	if (Test-Path -LiteralPath $fresh) { $why += "an output file was written" }
	if ($why.Count -eq 0) { Write-Host "PASS $($c.name)" -ForegroundColor Green }
	else {
		$failed++
		Write-Host "FAIL $($c.name): $($why -join '; ')" -ForegroundColor Red
		foreach ($l in ($text.Trim() -split "`r?`n" | Select-Object -Last 6)) { Write-Host "     $l" }
	}
}
if ((Get-Content -LiteralPath $db -Raw) -ne 'fake old db') { $failed++; Write-Host 'FAIL the old database was modified' -ForegroundColor Red }
if ((Get-Content -LiteralPath $openOut -Raw) -ne 'previous output') { $failed++; Write-Host 'FAIL the open output was modified' -ForegroundColor Red }
Write-Host ("{0} of {1} launcher checks passed" -f ($cases.Count - $failed), $cases.Count)
[System.IO.Directory]::Delete($junction)
Remove-Item -LiteralPath $Scratch -Recurse -Force
if ($failed -gt 0) { exit 1 }
exit 0
