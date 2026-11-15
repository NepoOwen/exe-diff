param(
	[Parameter(Position = 0)][string]$OldDb,
	[string]$OutDir,
	[string]$Output,
	[string]$NewDb,
	[int]$MinSimilarity = 80,
	[switch]$IncludeLikely,
	[switch]$Verify,
	[switch]$Strict,
	[switch]$Force,
	[string]$IdaDir
)

$root = $PSScriptRoot
$color = -not $env:NO_COLOR
function Say($text, $fg) { if ($color -and $fg) { Write-Host $text -ForegroundColor $fg } else { Write-Host $text } }
function Info($text) { Say "      $text" }
function Good($text) { Say "      $text" Green }
function Warn($text) { Say "      $text" Yellow }
function Bad($text) { Say "      $text" Red }
function Head($text) { Say $text White }
function Refuse($text) { Bad $text; exit 1 }

function Full($path, $base) {
	if ([System.IO.Path]::IsPathRooted($path)) { return [System.IO.Path]::GetFullPath($path) }
	if ($base) { return [System.IO.Path]::GetFullPath((Join-Path $base $path)) }
	return [System.IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path))
}

$fileIdCode = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace PortDb {
	public static class FileId {
		[StructLayout(LayoutKind.Sequential)]
		struct Info { public uint Attr, C1, C2, A1, A2, W1, W2, Serial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
		static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sec, uint disposition, uint flags, IntPtr template);
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool GetFileInformationByHandle(SafeFileHandle h, out Info info);
		public static string Of(string path) {
			using (SafeFileHandle h = CreateFileW(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
				if (h.IsInvalid) { return null; }
				Info i;
				if (!GetFileInformationByHandle(h, out i)) { return null; }
				return i.Serial.ToString("X8") + ":" + i.IndexHigh.ToString("X8") + i.IndexLow.ToString("X8");
			}
		}
	}
}
"@
if (-not ('PortDb.FileId' -as [type])) { Add-Type -TypeDefinition $fileIdCode }

function File-Id($path) {
	if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $null }
	try { return [PortDb.FileId]::Of($path) } catch { return $null }
}

function Same-File($a, $b) {
	if (-not $a -or -not $b) { return $false }
	if ([string]::Equals($a, $b, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
	$ia = File-Id $a
	return $ia -and $ia -eq (File-Id $b)
}

function Unpacked($db) {
	foreach ($ext in '.id0', '.id1', '.id2', '.nam', '.til') {
		$p = [System.IO.Path]::ChangeExtension($db, $ext)
		if (Test-Path -LiteralPath $p) { return $p }
	}
	return $null
}

function Read-Utf8($path) { return [System.IO.File]::ReadAllText($path, (New-Object System.Text.UTF8Encoding($false))) }

function Read-Pair($path) {
	$pair = @{}
	foreach ($line in (Read-Utf8 $path) -split "`r?`n") {
		$eq = $line.IndexOf('=')
		if ($eq -gt 0) { $pair[$line.Substring(0, $eq).Trim()] = $line.Substring($eq + 1).Trim() }
	}
	return $pair
}

function Ini-IdaDir($path) {
	if (-not (Test-Path -LiteralPath $path)) { return '' }
	foreach ($line in (Read-Utf8 $path).TrimStart([char]0xFEFF) -split "`r?`n") {
		$l = $line.Trim()
		if (-not $l -or $l -match '^[;#\[]') { continue }
		$eq = $l.IndexOf('=')
		if ($eq -lt 0 -or $l.Substring(0, $eq).Trim().ToLowerInvariant() -ne 'ida_dir') { continue }
		$v = $l.Substring($eq + 1).Trim()
		if ($v.Length -ge 2 -and $v.StartsWith('"') -and $v.EndsWith('"')) { $v = $v.Substring(1, $v.Length - 2).Trim() }
		return $v
	}
	return ''
}

function Inspect-Ida($dir) {
	if (-not $dir) { return $null }
	if ((Test-Path -LiteralPath $dir -PathType Leaf) -and (Split-Path $dir -Leaf) -ieq 'idat.exe') { $dir = Split-Path $dir -Parent }
	$idat = Join-Path $dir 'idat.exe'
	if (Test-Path -LiteralPath $idat -PathType Leaf) { return [System.IO.Path]::GetFullPath($idat) }
	return $null
}

function Find-Idat {
	if ($IdaDir) {
		$idat = Inspect-Ida $IdaDir
		if (-not $idat) { Refuse "-IdaDir: idat.exe is not in $IdaDir, it must be the folder IDA Pro is installed in" }
		return $idat
	}
	$ini = Full '..\..\exediff.ini' $root
	$configured = Ini-IdaDir $ini
	if ($configured) {
		$idat = Inspect-Ida $configured
		if (-not $idat) { Refuse "ida_dir in ${ini}: idat.exe is not in $configured, fix it or pass -IdaDir" }
		return $idat
	}
	$candidates = @()
	if ($env:IDADIR) { $candidates += $env:IDADIR }
	foreach ($base in @($env:ProgramW6432, $env:ProgramFiles) | Select-Object -Unique) {
		if ($base -and (Test-Path -LiteralPath $base)) {
			$candidates += @(Get-ChildItem -LiteralPath $base -Directory -Filter 'IDA*' | Sort-Object Name -Descending | ForEach-Object { $_.FullName })
		}
	}
	foreach ($c in $candidates) {
		$idat = Inspect-Ida $c
		if ($idat) { return $idat }
	}
	Refuse "IDA Pro was not found: set ida_dir in $ini or pass -IdaDir <folder holding idat.exe>"
}

function Log-Tail($path, $n) {
	if (-not (Test-Path -LiteralPath $path)) { return @() }
	return @(Get-Content -LiteralPath $path | Where-Object { $_.Trim() } | Select-Object -Last $n)
}

function Invoke-Idat($idat, $script, $db, $log, $tmp) {
	$stdin = Join-Path $tmp 'stdin.txt'
	if (-not (Test-Path -LiteralPath $stdin)) { [System.IO.File]::WriteAllText($stdin, '') }
	$argText = '-A -L"' + $log + '" -S"\"' + $script + '\"" "' + $db + '"'
	$p = Start-Process -FilePath $idat -ArgumentList $argText -NoNewWindow -PassThru -RedirectStandardInput $stdin `
		-RedirectStandardOutput (Join-Path $tmp 'idat.out.txt') -RedirectStandardError (Join-Path $tmp 'idat.err.txt')
	$null = $p.Handle
	$p.WaitForExit()
	return $p.ExitCode
}

function Read-Result($path) {
	if (-not (Test-Path -LiteralPath $path)) { return @{ status = ''; message = '' } }
	$lines = @((Read-Utf8 $path) -split "`r?`n")
	return @{ status = $lines[0].Trim(); message = (($lines | Select-Object -Skip 1) -join "`n").Trim() }
}

function Run-Pass($what, $script, $db, $resultName, [switch]$Soft) {
	$env:PORTDB_RESULT = Join-Path $tmp $resultName
	$log = Join-Path $tmp ($what + '.ida.log')
	$sw = [System.Diagnostics.Stopwatch]::StartNew()
	Info "$what ..."
	$code = Invoke-Idat $idat $script $db $log $tmp
	$r = Read-Result $env:PORTDB_RESULT
	if ($r.status -eq 'refused' -and $Soft) { return $r.message }
	if ($r.status -eq 'refused') {
		Bad $r.message
		Note-Log $what "refused: $($r.message)"
		Cleanup
		exit 1
	}
	if ($code -ne 0 -or $r.status -ne 'ok') {
		Bad ("$what failed after {0:0} s (idat exit code {1}{2})" -f $sw.Elapsed.TotalSeconds, $code, $(if ($r.status) { ", result $($r.status)" } else { ', no result' }))
		Note-Log $what "failed (idat exit code $code): no database was written`r`n$($r.message)"
		foreach ($l in @($r.message -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 8)) { Bad "  $l" }
		$tail = Log-Tail $log 8
		if ($tail.Count -eq 0) { $tail = Log-Tail (Join-Path $tmp 'idat.err.txt') 8 }
		foreach ($l in $tail) { Bad "  $l" }
		if (Test-Path -LiteralPath $log) {
			Copy-Item -LiteralPath $log -Destination $idaLog -Force
			Bad "IDA log: $idaLog"
		}
		Cleanup
		exit 2
	}
	Good ("{0} in {1:0} s: {2}" -f $what, $sw.Elapsed.TotalSeconds, $r.message)
}

function Note-Log($what, $text) {
	if ($logStarted -and (Test-Path -LiteralPath $logPath)) {
		[System.IO.File]::AppendAllText($logPath, ($text.TrimEnd() -replace "`r?`n", "`r`n") + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
	}
}

function Read-Summary($path) {
	if (-not (Test-Path -LiteralPath $path)) { return $null }
	$s = @{ context = @(); info = @(); warning = @() }
	foreach ($line in (Read-Utf8 $path) -split "`r?`n") {
		$eq = $line.IndexOf('=')
		if ($eq -le 0) { continue }
		$key = $line.Substring(0, $eq)
		if ($key -eq 'context' -or $key -eq 'info' -or $key -eq 'warning') { $s[$key] += $line.Substring($eq + 1) } else { $s[$key] = $line.Substring($eq + 1) }
	}
	return $s
}

function Plural($n, $word, $many) { if ($n -eq 1) { return "$n $word" } return "$n $many" }

function Cleanup {
	if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

if (-not $OldDb) {
	Head 'usage: port-ida-database <old.i64> [-OutDir <exediff out folder>] [-Output <new.i64>] [-NewDb <analysed new .i64>]'
	Info '[-MinSimilarity 80] [-IncludeLikely] [-Verify] [-Strict] [-Force] [-IdaDir <IDA folder>]'
	exit 1
}
if ($MinSimilarity -lt 0 -or $MinSimilarity -gt 100) { Refuse "-MinSimilarity must be 0 to 100, got $MinSimilarity" }

$OldDb = Full $OldDb
if (-not (Test-Path -LiteralPath $OldDb -PathType Leaf)) { Refuse "old database not found: $OldDb" }
$open = Unpacked $OldDb
if ($open) { Refuse "the old database looks open in IDA ($(Split-Path $open -Leaf) sits next to it): close it in IDA first" }

if ($OutDir) { $OutDir = Full $OutDir } else { $OutDir = Full '..\..\out' $root }
$map = Join-Path $OutDir 'map.csv'
$pairPath = Join-Path $OutDir 'pair.txt'
if (-not (Test-Path -LiteralPath $map -PathType Leaf)) { Refuse "no map.csv in ${OutDir}: run exediff on the old and new exe first, or pass -OutDir" }
if (-not (Test-Path -LiteralPath $pairPath -PathType Leaf)) { Refuse "no pair.txt in ${OutDir}: it is written by a newer exediff, run exediff again" }
$header = (Get-Content -LiteralPath $map -TotalCount 1).TrimStart([char]0xFEFF).Trim()
$columns = @($header -split ',' | ForEach-Object { $_.Trim() })
if ($columns -notcontains 'method') { Refuse 'map.csv is from an older exediff: it has no method column; run exediff again' }
$pair = Read-Pair $pairPath
foreach ($key in 'old_exe', 'old_md5', 'new_exe', 'new_md5', 'new_work') {
	if (-not $pair[$key]) { Refuse "pair.txt in $OutDir has no ${key}: run exediff again" }
}
$oldName = Split-Path $pair['old_exe'] -Leaf
$newName = Split-Path $pair['new_exe'] -Leaf

$cached = Full (Join-Path $pair['new_work'] 'input.exe.i64')
$newDbGiven = [bool]$NewDb
if ($NewDb) {
	$NewDb = Full $NewDb
	if (-not (Test-Path -LiteralPath $NewDb -PathType Leaf)) { Refuse "-NewDb not found: $NewDb" }
} else {
	$NewDb = $cached
	if (-not (Test-Path -LiteralPath $NewDb -PathType Leaf)) { Refuse "no analysed database of $newName at ${NewDb}: run exediff with IDA first" }
}
$open = Unpacked $NewDb
if ($open) { Refuse "the new database looks open in IDA ($(Split-Path $open -Leaf) sits next to it): close it in IDA first" }

$cachedOld = ''
$noBaseline = ''
if ($pair['old_work']) { $cachedOld = Full (Join-Path $pair['old_work'] 'input.exe.i64') }
if (-not $cachedOld -or -not (Test-Path -LiteralPath $cachedOld -PathType Leaf)) {
	$noBaseline = "no analysis cache for ${oldName}: IDA-made names, comments and types cannot be told from yours; run exediff with IDA first"
} elseif (Unpacked $cachedOld) {
	$noBaseline = "the analysis cache of $oldName looks open in IDA ($(Split-Path (Unpacked $cachedOld) -Leaf) sits next to it): IDA-made names, comments and types cannot be told from yours"
}
if ($noBaseline -and $Strict) { Refuse "$noBaseline (-Strict)" }

if ($Output) { $Output = Full $Output } else { $Output = Join-Path (Join-Path $root 'output') ($newName + '.i64') }
$protected = @($OldDb, $NewDb, $cached, $cachedOld, (Full (Join-Path $pair['new_work'] 'input.exe')), (Full $pair['old_exe']), (Full $pair['new_exe']))
if ($pair['old_work']) { $protected += Full (Join-Path $pair['old_work'] 'input.exe') }
foreach ($keep in $protected) {
	if (Same-File $Output $keep) { Refuse "-Output would overwrite $keep, pick another file" }
}
$open = Unpacked $Output
if ($open) { Refuse "the output looks open in IDA ($(Split-Path $open -Leaf) sits next to it): close it in IDA first, or pick another -Output" }
if ((Test-Path -LiteralPath $Output) -and -not $Force) { Refuse "$Output already exists: pass -Force to replace it" }

$idat = Find-Idat

$outFolder = Split-Path $Output -Parent
$dumpPath = Join-Path $outFolder 'port-ida-database.dump.json'
$logPath = Join-Path $outFolder 'port-ida-database.log'
$idaLog = Join-Path $outFolder 'port-ida-database.ida.log'
$tmp = Join-Path $outFolder '.port-ida-database.tmp'

Head "port-ida-database: $OldDb"
Info "pair: $oldName -> $newName"
Info "new database: $NewDb"
Info "output: $Output"
Info "using $idat"

if (-not (Test-Path -LiteralPath $outFolder)) { [void](New-Item -ItemType Directory -Path $outFolder -Force) }
Cleanup
[void](New-Item -ItemType Directory -Path $tmp)

$env:PORTDB_DUMP = $dumpPath
$env:PORTDB_PAIR = $pairPath
$env:PORTDB_MAP = $map
$env:PORTDB_LOG = $logPath
$env:PORTDB_MIN_SIMILARITY = [string]$MinSimilarity
$env:PORTDB_INCLUDE_LIKELY = $(if ($IncludeLikely) { '1' } else { '0' })
$env:PORTDB_VERIFY = $(if ($Verify) { '1' } else { '0' })
$env:PORTDB_STRICT = $(if ($Strict) { '1' } else { '0' })
$env:PORTDB_NEWDB_GIVEN = $(if ($newDbGiven) { '1' } else { '0' })
$env:PORTDB_OLD_EXE_NAME = $oldName
$env:PORTDB_BASELINE = ''
$env:PORTDB_BASELINE_WARNING = ''
$env:PORTDB_STATE = Join-Path $tmp 'state.json'
$env:PORTDB_SUMMARY = Join-Path $tmp 'summary.txt'

$partial = $Output + '.partial'
$logStarted = $false
function Fail-File($text) {
	Bad $text
	if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue }
	if ($logStarted) { Note-Log 'apply' "failed: $text" }
	Cleanup
	exit 2
}

function Copy-Db($from, $to) {
	try { Copy-Item -LiteralPath $from -Destination $to -ErrorAction Stop }
	catch { Fail-File "cannot copy $from to ${to}: $(Why $_)" }
}

function Why($err) {
	$e = $err.Exception
	if ($e.InnerException) { $e = $e.InnerException }
	return $e.Message.Trim()
}

try {
	$oldCopy = Join-Path $tmp 'old.i64'
	Copy-Db $OldDb $oldCopy
	if (-not $noBaseline) {
		$baseCopy = Join-Path $tmp 'baseline.i64'
		Copy-Db $cachedOld $baseCopy
		$env:PORTDB_BASELINE = Join-Path $tmp 'baseline.json'
		$refused = Run-Pass 'baseline' (Join-Path $root 'baseline_db.py') $baseCopy 'baseline.result.txt' -Soft
		Remove-Item -LiteralPath $baseCopy -Force
		if ($refused) {
			$env:PORTDB_BASELINE = ''
			$noBaseline = "$refused; IDA-made names, comments and types cannot be told from yours: run exediff with IDA again"
			if ($Strict) { Bad "$noBaseline (-Strict)"; Cleanup; exit 1 }
		}
	}
	if ($noBaseline) {
		Warn $noBaseline
		$env:PORTDB_BASELINE_WARNING = $noBaseline
	}
	Run-Pass 'export' (Join-Path $root 'export_db.py') $oldCopy 'export.result.txt'
	Remove-Item -LiteralPath $oldCopy -Force

	$yes = { param($on) if ($on) { 'yes' } else { 'no' } }
	$options = 'min similarity {0}, include likely {1}, verify {2}, strict {3}' -f $MinSimilarity, (& $yes $IncludeLikely), (& $yes $Verify), (& $yes $Strict)
	$header = @(
		('port-ida-database {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm')),
		"old database: $OldDb",
		"new database: $NewDb",
		"pair: $oldName -> $newName",
		"output: $Output",
		"options: $options",
		''
	)
	[System.IO.File]::WriteAllText($logPath, (($header -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
	$logStarted = $true

	$newCopy = Join-Path $tmp 'new.i64'
	Copy-Db $NewDb $newCopy
	Run-Pass 'apply' (Join-Path $root 'apply_db.py') $newCopy 'apply.result.txt'
	$left = Unpacked $newCopy
	if ($left) { Fail-File "IDA left $(Split-Path $left -Leaf) behind: the new database was not closed cleanly" }
	$sum = Read-Summary $env:PORTDB_SUMMARY
	if ($sum) {
		foreach ($c in $sum.context) { Warn $c }
		foreach ($c in $sum.warning) { Warn $c }
		$rest = [int]$sum.warnings - $sum.context.Count - $sum.warning.Count
		if ($rest -gt 0) { Warn "$(Plural $rest 'more warning' 'more warnings'): see the log for the rest" }
		foreach ($c in $sum.info) { Info "note: $c" }
	}
	if ($Verify) {
		$verifyCopy = Join-Path $tmp 'verify.i64'
		Copy-Db $newCopy $verifyCopy
		Run-Pass 'verify' (Join-Path $root 'verify_db.py') $verifyCopy 'verify.result.txt'
		Remove-Item -LiteralPath $verifyCopy -Force -ErrorAction SilentlyContinue
		$sum = Read-Summary $env:PORTDB_SUMMARY
	}

	try {
		if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force -ErrorAction Stop }
		[System.IO.File]::Move($newCopy, $partial)
	} catch { Fail-File "cannot move the finished database to ${partial}: $(Why $_)" }
	try {
		if (Test-Path -LiteralPath $Output) { [System.IO.File]::Replace($partial, $Output, [NullString]::Value) }
		else { [System.IO.File]::Move($partial, $Output) }
	} catch {
		$first = Why $_
		if (-not (Test-Path -LiteralPath $Output) -or -not (Test-Path -LiteralPath $partial)) { Fail-File "cannot write ${Output}: $first (is it open in IDA?)" }
		try { [System.IO.File]::Delete($Output) } catch { Fail-File "cannot write ${Output}: $first (is it open in IDA?)" }
		try { [System.IO.File]::Move($partial, $Output) }
		catch { Bad "cannot write ${Output}: $first; the old file was deleted, but moving the new one there failed: $(Why $_); the finished database is $partial"; Cleanup; exit 2 }
	}
	if (-not (Test-Path -LiteralPath $Output) -or (Test-Path -LiteralPath $partial)) { Fail-File "$Output was not written" }
} finally {
	Cleanup
}

if (Test-Path -LiteralPath $idaLog) { Remove-Item -LiteralPath $idaLog -Force }
Head ''
Good "written: $Output"
Info "log: $logPath"
if ($sum) {
	$warnings = [int]$sum.warnings
	if ($sum.mismatches -eq '') { $checked = 'mismatches not checked (-Verify)'; $mismatches = 0 }
	else {
		$mismatches = [int]$sum.mismatches
		$checked = '{0} in {1}' -f (Plural $mismatches 'mismatch' 'mismatches'), (Plural ([int]$sum.compared) 'compared function' 'compared functions')
	}
	$line = '{0} ported, {1} listed for review, {2}, {3}' -f $sum.ported, $sum.listed, (Plural $warnings 'warning' 'warnings'), $checked
	if ($warnings -or $mismatches) { Warn $line } else { Good $line }
	if ($sum.made -and $sum.made -ne '0') { Info "$($sum.made) notes and folders made by the script (not counted as ported)" }
	if ($sum.ported -eq '0') {
		if ($sum.empty -eq '1' -and $sum.baseline -eq '0') { Warn "0 ported: nothing found that could be told apart from IDA's own (no analysis cache)" }
		elseif ($sum.empty -eq '1') { Info '0 ported: the old database has no annotations of yours, only what IDA made itself' }
		else { Warn '0 ported: see Needs review in the log' }
	}
}
exit 0
