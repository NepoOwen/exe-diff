# exediff

Compares two builds of a Windows executable or DLL and reports which functions were **added**, **removed** or **changed**, with GitHub-style diffs of the decompiled C and of the assembly.

It was written to follow `Trove_x64.exe` between game updates. It works on x64 PE files (functions come from `.pdata`) and on 32-bit (x86) exes and DLLs (functions are found by analysis, see [docs/x86.md](docs/x86.md)). One `exediff.exe` does both: it reads the architecture from the files. Both files of a pair must have the same architecture.

`exediff.exe` is the only file you run. It does the reading, matching and diffing itself, and drives IDA Pro in the background to decompile just the functions that changed.

## What you get

For `exediff.exe old.exe new.exe`, in the `out` folder next to `exediff.exe`:

| File | What it is |
|---|---|
| `report.html` | The report: every changed, added and removed function with a C diff, an assembly diff and a code signature. |
| `map.csv` | Every function of both exes, what it was matched to and how it was matched. The `method` column says how a pair was found (`exact-unique`, `exact-group`, `refined`, `propagated`, `similar`), `similarity` is the percentage for changed functions. |
| `pair.txt` | The two exes, their md5 and their IDA work folders, for `port-ida-database`. |
| `agent.md` | A short summary for an AI assistant, with line ranges into the file below. |
| `report-do-not-read-in-full.md` | The full report as Markdown (large). |

## How it works

1. **Compare.** The exes are parsed, split into functions, and matched. Branch and call offsets, RIP-relative displacements and relocated addresses are masked first, so a function that only *moved* is not reported as changed.
2. **Decompile.** IDA Pro (headless `idat.exe`) decompiles only the functions that really differ. The first run analyses each exe once, which takes a few minutes. The analysis is saved and reused.
3. **Report.** The decompiled C, the assembly diff and a signature for each function go into the report.

Every function ends up matched, added, removed, or listed as unmatched with a reason. A function that fails to decompile still gets its assembly diff and the failure reason.

Every listed function also gets the code signature that the *Signature Maker* IDA plugin would make for it (`Create unique signature for current code address`). exediff does this itself, so the plugin does not need to be installed. See [docs/signatures.md](docs/signatures.md).

## Requirements

- Windows 10 or 11, x64 (`exediff.exe` is a 64-bit program; it analyses 32-bit and 64-bit files).
- **For the C diffs and signatures:** IDA Pro 9.x with the Hex-Rays decompiler (`hexx64.dll`, which also decompiles 32-bit code; tested with 9.2). Without IDA, exediff still works and the report has the assembly diff only.
- **To build it:** Visual Studio with the MSVC v145 toolset (C++20).

## Usage

```
exediff <old.exe> <new.exe> [options]

  --out <dir>   where the report goes (default: out next to exediff.exe)
  --work <dir>  where the IDA files go (default: work next to exediff.exe)
  --ida <dir>   the IDA Pro install folder, overrides ida_dir in exediff.ini
  --no-ida      skip IDA: the report has assembly only
```

Keep the `ida` folder (it holds the two IDA scripts) next to `exediff.exe`. A build puts `exediff.exe`, `ida` and `scripts` together in `build\`, and that folder is all you need to run it or hand it on.

The exit code is `0` on success (also when IDA was not available and the report is assembly only), `1` for bad arguments, files or settings, and `2` when IDA ran but failed for one of the exes, so the report is incomplete.

### Settings

On the first run exediff creates `exediff.ini` next to `exediff.exe`:

```ini
ida_dir = C:\Program Files\IDA Professional 9.2
```

`ida_dir` is the folder IDA Pro is installed in, the one that holds `idat.exe`. If it is empty, exediff looks for IDA itself: the `IDADIR` environment variable, `IDA*` folders in `Program Files` and `%LOCALAPPDATA%\Programs`, then `PATH`. `--ida` on the command line wins over the file.

### When something is missing

| Situation | What exediff does |
|---|---|
| `ida_dir` or `--ida` points somewhere that has no `idat.exe` | Stops before comparing and says what is wrong. |
| No IDA is configured and none is found | Carries on and writes the assembly-only report, with a warning that says how to set `ida_dir`. |
| The `ida` scripts folder is missing | Stops and says so. |
| `hexx64.dll` (the Hex-Rays decompiler) is not in the IDA folder, or IDA has no licence for it | Warns, and the report has signatures and assembly but no C. |
| IDA starts but fails | Names the exe, shows the last lines of IDA's log, still writes the report, and exits with `2`. |
| Old is x64 and new is x86 (or the reverse) | Stops before comparing: `old is x64 but new is x86: both files must have the same architecture`, exit code 1. |

Press Ctrl+C to stop; the IDA process started by exediff is stopped with it.

The `update-signatures` script in `scripts\` works on x64 reports only.

## Porting your IDA database

After exediff has compared the two exes with IDA, `port-ida-database` carries the names, comments, types, prototypes and Hex-Rays edits you made in the old exe's IDA database over to a database of the new exe:

```
scripts\port-ida-database\port-ida-database.bat "C:\re\old.i64"
```

The result is `scripts\port-ida-database\output\<new exe>.i64` with a log of what was ported and what needs a look by hand. Only annotations on functions that are certainly the same are ported in full; changed functions get names and comments with a note. Your old `.i64` is never modified. See [docs/port-ida-database.md](docs/port-ida-database.md).

## Building

Open `exediff.sln` in Visual Studio, or run `build_project.bat`. Only `Release|x64` is supported. The output is in `build\`.

```
build\exediff_tests.exe [name filter]
```

runs the tests. A few use sample exes (`Trove_x64.old.exe` and `Trove_x64.new.exe`, `Trove_x86.old.exe` and `Trove_x86.new.exe` in the working directory) and are skipped when those are not there. The small 32-bit test programs are in `tests\data\x86`.

The build copies `ida` and `scripts` next to `exediff.exe`, so `build\` holds everything: `exediff.exe`, `ida\` and `scripts\`. To hand exediff to someone else, give them that folder.

## Layout

| Folder | |
|---|---|
| `src/pe` | PE loading: sections, `.pdata`, `.reloc` |
| `src/disasm` | Zydis decoding and operand masking |
| `src/func` | Functions from `.pdata` (x64) or found by analysis (x86, `seeds`), masked hashes |
| `src/match` | Exact pairing, refinement, caller propagation, similarity pairing |
| `src/text`, `src/diff` | Assembly text with matched names, line diff, decompiler-output clean-up |
| `src/ida` | IDA install detection, running `idat`, the request and result files |
| `src/sig` | Parsing and searching IDA-format signatures |
| `src/report` | HTML and Markdown reports, `map.csv` |
| `src/config`, `src/console` | `exediff.ini` and the console output |
| `ida` | The Python scripts that run inside IDA |
| `scripts` | Separate tools, one folder each. `update-signatures` rewrites the signatures in your own source files (put them in `scripts\update-signatures\input`, the result is in `output`) from the latest report |
| `scripts/port-ida-database` | Ports your IDA annotations from the old exe's database to the new one (`lib\` holds the Python that runs inside IDA) |
| `tests` | The test exe, and the Python tests of `port-ida-database` (`tests\port_ida_database`) |

More detail in [docs/](docs/).

## License

[MIT](LICENSE), copyright (c) 2026 NepoOwen.

[Zydis](https://github.com/zyantific/zydis) (in `external/zydis`) is MIT licensed, original author Florian Bernd.
