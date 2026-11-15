param(
	[string]$InputDir = 'input',
	[string]$OutputDir = 'output',
	[string]$Report = '..\..\out\report-do-not-read-in-full.md',
	[switch]$DryRun
)

$root = $PSScriptRoot
if (-not [System.IO.Path]::IsPathRooted($InputDir)) { $InputDir = Join-Path $root $InputDir }
if (-not [System.IO.Path]::IsPathRooted($OutputDir)) { $OutputDir = Join-Path $root $OutputDir }
if (-not [System.IO.Path]::IsPathRooted($Report)) { $Report = Join-Path $root $Report }

function Info($text) { Write-Host "      $text" }
function Good($text) { Write-Host "      $text" -ForegroundColor Green }
function Warn($text) { Write-Host "      $text" -ForegroundColor Yellow }
function Bad($text) { Write-Host "      $text" -ForegroundColor Red }
function Head($text) { Write-Host $text -ForegroundColor White }

if (-not (Test-Path -LiteralPath $Report)) { Bad "no report at $Report"; exit 1 }
if (-not (Test-Path -LiteralPath $InputDir)) { Bad "no input folder at $InputDir"; exit 1 }

$tok = '(?:[0-9A-Fa-f]{2}|\?{1,2})'
$sigRun = New-Object System.Text.RegularExpressions.Regex("(?<![0-9A-Fa-f?])$tok(?:[ \t]+$tok){5,}(?![0-9A-Fa-f?])")

function Normalize-Sig($text) {
	$s = $text.Trim().ToUpperInvariant() -replace '[ \t]+', ' '
	$s = $s -replace '\?\?', '?'
	return $s
}

function Read-TextFile($path) {
	$bytes = [System.IO.File]::ReadAllBytes($path)
	if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
		return @{ text = [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3); enc = (New-Object System.Text.UTF8Encoding($true)) }
	}
	if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
		return @{ text = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2); enc = (New-Object System.Text.UnicodeEncoding($false, $true)) }
	}
	return @{ text = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes); enc = [System.Text.Encoding]::GetEncoding(28591) }
}

function Read-Report($path) {
	$entries = New-Object System.Collections.ArrayList
	$header = @{ old = ''; new = ''; summary = '' }
	$cur = $null
	foreach ($line in [System.IO.File]::ReadLines($path)) {
		if ($line.StartsWith('## ')) {
			$m = [regex]::Match($line, '^## (?<kind>[A-Za-z ]+?) (?<name>\S+)\s*$')
			if ($m.Success) {
				$cur = [pscustomobject]@{
					kind = $m.Groups['kind'].Value
					name = $m.Groups['name'].Value
					addr = ''
					old = $null
					new = $null
					unchanged = $null
				}
				[void]$entries.Add($cur)
			} else { $cur = $null }
			continue
		}
		if ($line.StartsWith('- old: ') -and $header.old -eq '') { $header.old = $line.Substring(7) }
		elseif ($line.StartsWith('- new: ') -and $header.new -eq '') { $header.new = $line.Substring(7) }
		elseif ($line.StartsWith('- same ') -and $header.summary -eq '') { $header.summary = $line.Substring(2) }
		if ($null -eq $cur) { continue }
		if ($line.StartsWith('- old 0x')) {
			$m = [regex]::Match($line, '^- old (0x[0-9A-Fa-f]+) \(\d+ bytes\), new (0x[0-9A-Fa-f]+)')
			if ($m.Success) { $cur.addr = $m.Groups[1].Value }
		}
		if ($line.StartsWith('- old signature: ')) {
			$cur.old = Normalize-Sig $line.Substring(17).Trim('`')
		}
		elseif ($line.StartsWith('- new signature: ')) {
			$cur.new = Normalize-Sig $line.Substring(17).Trim('`')
		}
		elseif ($line.StartsWith('- signature (unchanged): ')) {
			$cur.unchanged = Normalize-Sig $line.Substring(27).Trim('`')
		}
	}
	return @{ entries = $entries; header = $header }
}

function Build-Index($entries) {
	$bySig = @{}
	$flat = New-Object System.Collections.ArrayList
	foreach ($e in $entries) {
		$pairs = @(@('old', $e.old), @('new', $e.new), @('unchanged', $e.unchanged))
		if ($e.old -and $e.new -eq $e.old) { $pairs = @(@('old', $e.old), @('unchanged', $e.unchanged)) }
		foreach ($pair in $pairs) {
			$role = $pair[0]
			$sig = $pair[1]
			if (-not $sig) { continue }
			$hit = [pscustomobject]@{ entry = $e; role = $role }
			[void]$flat.Add($hit)
			if (-not $bySig.ContainsKey($sig)) { $bySig[$sig] = New-Object System.Collections.ArrayList }
			[void]$bySig[$sig].Add($hit)
		}
	}
	return @{ bySig = $bySig; flat = $flat }
}

function Resolve-Sig($sig, $index) {
	if ($index.bySig.ContainsKey($sig)) {
		$hits = @($index.bySig[$sig])
		if ($hits.Count -eq 1) {
			$e = $hits[0].entry
			if ($hits[0].role -eq 'old' -and $e.new) {
				return [pscustomobject]@{ kind = 'update'; text = $e.new; candidates = @($hits) }
			}
			if ($hits[0].role -eq 'old') {
				return [pscustomobject]@{ kind = 'removed'; candidates = @($hits) }
			}
			return [pscustomobject]@{ kind = 'current'; candidates = @($hits) }
		}
		return [pscustomobject]@{ kind = 'ambiguous'; candidates = $hits }
	}

	$padded = ' ' + $sig + ' '
	$inside = New-Object System.Collections.ArrayList
	$outside = New-Object System.Collections.ArrayList
	foreach ($hit in $index.flat) {
		$s = $hit.entry.PSObject.Properties[$hit.role].Value
		if (-not $s) { continue }
		$ws = ' ' + $s + ' '
		if ($ws.Contains($padded)) { [void]$inside.Add($hit) }
		elseif ($padded.Contains($ws)) { [void]$outside.Add($hit) }
	}
	if ($inside.Count -gt 0) { return [pscustomobject]@{ kind = 'prefix'; candidates = $inside } }
	if ($outside.Count -gt 0) { return [pscustomobject]@{ kind = 'contains'; candidates = $outside } }
	return [pscustomobject]@{ kind = 'unknown'; candidates = @() }
}

function Format-NewSig($sig, $like) {
	if ($like.Contains('??')) { $sig = $sig -replace '\?', '??' }
	if ($like -cmatch '[a-f]') { $sig = $sig.ToLowerInvariant() }
	return $sig
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$parsed = Read-Report $Report
$index = Build-Index $parsed.entries

Head "update-signatures: $InputDir"
Head "      output: $OutputDir"
Head "      report: $Report"
if ($parsed.header.old) { Info "old: $($parsed.header.old)" }
if ($parsed.header.new) { Info "new: $($parsed.header.new)" }
if ($parsed.header.summary) { Info $parsed.header.summary }
Info "$($parsed.entries.Count) entries, $($index.flat.Count) signatures, read in $('{0:0.0}' -f $sw.Elapsed.TotalSeconds) s"
if ($DryRun) { Warn 'dry run: nothing is written' }
else {
	if (-not (Test-Path -LiteralPath $OutputDir)) { [void](New-Item -ItemType Directory -Path $OutputDir) }
	$stale = @(Get-ChildItem -LiteralPath $OutputDir -File -Recurse)
	if ($stale.Count -gt 0) { Warn "output folder already has $($stale.Count) file(s), they are overwritten but not removed" }
}

$totals = @{ update = 0; current = 0; removed = 0; ambiguous = 0; prefix = 0; contains = 0; unknown = 0; files = 0; changedFiles = 0; copied = 0; logs = 0 }
$attention = New-Object System.Collections.ArrayList
$written = @{}

$files = @(Get-ChildItem -LiteralPath $InputDir -File -Recurse | Where-Object { -not $_.FullName.StartsWith($OutputDir, [System.StringComparison]::OrdinalIgnoreCase) } | Sort-Object FullName)
if ($files.Count -eq 0) { Bad "no files in $InputDir"; exit 1 }

foreach ($file in $files) {
	$read = Read-TextFile $file.FullName
	$lines = $read.text.Split("`n")
	$decided = @{}
	$fileUpdated = 0
	$results = New-Object System.Collections.ArrayList

	for ($n = 0; $n -lt $lines.Count; $n++) {
		$line = $lines[$n]
		if ($line.IndexOfAny([char[]]'0123456789ABCDEFabcdef?') -lt 0) { continue }
		$matches_ = $sigRun.Matches($line)
		if ($matches_.Count -eq 0) { continue }
		for ($i = $matches_.Count - 1; $i -ge 0; $i--) {
			$m = $matches_[$i]
			$raw = $m.Value
			$sig = Normalize-Sig $raw
			if (-not $decided.ContainsKey($raw)) { $decided[$raw] = Resolve-Sig $sig $index }
			$res = $decided[$raw]
			$totals[$res.kind] = $totals[$res.kind] + 1
			if ($res.kind -eq 'update') {
				$lines[$n] = $lines[$n].Substring(0, $m.Index) + (Format-NewSig $res.text $raw) + $lines[$n].Substring($m.Index + $m.Length)
				$fileUpdated++
			}
			[void]$results.Add([pscustomobject]@{ line = $n + 1; raw = $raw; result = $res })
		}
	}

	if ($results.Count -eq 0) { continue }
	$totals.files++

	$relative = $file.FullName.Substring($InputDir.Length).TrimStart('\', '/')
	$dest = Join-Path $OutputDir $relative
	$logPath = $dest + '.log'

	Head ''
	Head (Split-Path $file.FullName -Leaf)
	$missing = New-Object System.Collections.ArrayList
	$errors = New-Object System.Collections.ArrayList
	$counts = @{ update = 0; current = 0; unknown = 0; need = 0 }

	foreach ($r in $results) {
		$cands = @($r.result.candidates | Sort-Object @{ Expression = { if ($_.role -eq 'old') { 0 } else { 1 } } }, @{ Expression = { $_.entry.name } })
		$names = @($cands | ForEach-Object { $_.entry.name } | Select-Object -Unique)
		$where = 'line ' + $r.line
		switch ($r.result.kind) {
			'update' {
				$counts.update++
				Good ('{0,-12} updated    {1}' -f $where, ($names -join ', '))
			}
			'current' {
				$counts.current++
				Info ('{0,-12} current    {1}' -f $where, ($names -join ', '))
			}
			'unknown' {
				$counts.unknown++
				[void]$missing.Add($r)
			}
			default {
				$counts.need++
				$reason = @{
					removed   = 'no new signature: the function is gone from the new exe'
					ambiguous = 'the signature matches more than one entry'
					prefix    = 'the report signature is longer, ours is only its start'
					contains  = 'our signature is longer than the report signature'
				}[$r.result.kind]
				$shown = (@($names | Select-Object -First 4) -join ', ')
				if ($names.Count -gt 4) { $shown += ", +$($names.Count - 4) more" }
				Warn ('{0,-12} {1} {2} - {3}' -f $where, $r.result.kind, $shown, $reason)
				[void]$errors.Add(('{0}:{1}  {2}  {3}' -f $file.Name, $r.line, $r.result.kind, $shown))
				[void]$attention.Add([pscustomobject]@{ file = $file.Name; line = $r.line; kind = $r.result.kind; names = $shown })
			}
		}
	}
	if ($missing.Count -gt 0) {
		$lineList = @($missing | ForEach-Object { $_.line })
		$listed = (@($lineList | Select-Object -First 12) -join ', ')
		if ($lineList.Count -gt 12) { $listed += ', ...' }
		Warn ('{0,-12} unknown    not in the report: line(s) {1}' -f ('(' + $lineList.Count + ')'), $listed)
	}

	if (-not $DryRun) {
		$parent = Split-Path $dest -Parent
		if (-not (Test-Path -LiteralPath $parent)) { [void](New-Item -ItemType Directory -Path $parent -Force) }
		if ($fileUpdated -gt 0) {
			[System.IO.File]::WriteAllText($dest, ($lines -join "`n"), $read.enc)
			$written[$relative] = $true
			$totals.changedFiles++
		}
		if ($errors.Count -gt 0) {
			$pair = ''
			if ($parsed.header.old -and $parsed.header.new) {
				$oldName = [System.IO.Path]::GetFileName(($parsed.header.old -split ' \(')[0].Trim())
				$newName = [System.IO.Path]::GetFileName(($parsed.header.new -split ' \(')[0].Trim())
				$pair = "  $oldName -> $newName"
			}
			$log = New-Object System.Collections.ArrayList
			[void]$log.Add(('update-signatures {0}{1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $pair))
			foreach ($e in $errors) { [void]$log.Add($e) }
			[void]$log.Add('')
			[void]$log.Add(('{0} updated, {1} already current, {2} not in the report, {3} need a hand' -f $counts.update, $counts.current, $counts.unknown, $counts.need))
			[System.IO.File]::WriteAllText($logPath, (($log -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
			$totals.logs++
			Info "log: ${relative}.log"
		} elseif (Test-Path -LiteralPath $logPath) {
			Remove-Item -LiteralPath $logPath
		}
	}
	if ($fileUpdated -gt 0) { Info "$fileUpdated signature(s) rewritten" }
}

Head ''
if ($DryRun) { Info 'dry run: nothing written' }
else {
	foreach ($file in $files) {
		$relative = $file.FullName.Substring($InputDir.Length).TrimStart('\', '/')
		if ($written.ContainsKey($relative)) { continue }
		$dest = Join-Path $OutputDir $relative
		$parent = Split-Path $dest -Parent
		if (-not (Test-Path -LiteralPath $parent)) { [void](New-Item -ItemType Directory -Path $parent -Force) }
		Copy-Item -LiteralPath $file.FullName -Destination $dest -Force
		$totals.copied++
	}
	Info "output: $OutputDir"
	Info "$($totals.changedFiles) written with new signatures, $($totals.copied) copied unchanged, $($totals.logs) error log(s)"
}
Good "$($totals.update) updated, $($totals.current) already current, $($totals.unknown) not in the report"
$bad = $totals.removed + $totals.ambiguous + $totals.prefix + $totals.contains
if ($bad -gt 0) {
	Warn "$bad signature(s) need a hand: $($totals.prefix) longer in the report, $($totals.contains) longer here, $($totals.ambiguous) ambiguous, $($totals.removed) removed"
	foreach ($a in $attention) { Warn ('  {0}:{1}  {2}  {3}' -f $a.file, $a.line, $a.kind, $a.names) }
	exit 1
}
exit 0
