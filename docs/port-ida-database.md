# Porting your IDA database

`scripts\port-ida-database\port-ida-database.ps1` carries the work you did in the IDA database of the old exe (names, comments, types, prototypes, Hex-Rays edits) over to a database of the new exe. It uses the function pairs that exediff found, and it only applies an annotation where it is sure the place is the same.

Your old `.i64` is never modified. It is copied, and every IDA pass runs on a copy. So is exediff's cached analysis (`work\<hash>\input.exe.i64`).

## Order of steps

1. Run exediff on the two exes, with IDA: `exediff.exe old.exe new.exe`. This writes `out\map.csv` and `out\pair.txt`, and analyses both exes in IDA. The analysis of the new exe becomes the base of the output. The analysis of the old exe is the baseline that tells your annotations from IDA's own.
2. Close the old database in IDA.
3. Run the script:

```
scripts\port-ida-database\port-ida-database.bat "C:\re\Trove_old.i64"
scripts\port-ida-database\port-ida-database.bat "C:\re\Trove_old.i64" -MinSimilarity 90 -IncludeLikely -Verify
```

The `.bat` runs `port-ida-database.ps1` with the same arguments; from PowerShell you can call `.\port-ida-database.ps1` directly. The result is `scripts\port-ida-database\output\<new exe>.i64`, with `port-ida-database.log` and `port-ida-database.dump.json` next to it. Open the `.i64` in IDA and read the log.

## Options

| Option | Meaning |
|---|---|
| `-OutDir <folder>` | The exediff `out` folder that holds `map.csv` and `pair.txt`. Default: `out` next to `exediff.exe`. |
| `-Output <file.i64>` | Where the new database goes. Default: `output\<new exe>.i64` next to the script. |
| `-NewDb <file.i64>` | Start from another database of the new exe instead of exediff's analysis, for example one you already worked in. It is copied, not changed. |
| `-MinSimilarity 80` | Changed functions below this similarity (percent) are not ported. |
| `-IncludeLikely` | Also port functions that are one of several identical copies (see "likely" below). |
| `-Verify` | Decompile the functions that got prototypes or Hex-Rays edits, in both databases, and list where the pseudocode differs. Off by default; it adds time. |
| `-Strict` | Stop with exit code 1, and write no database, when the two databases differ in type libraries, compiler, ABI or bitness, or when there is no baseline. |
| `-Force` | Replace an existing output file. |
| `-IdaDir <folder>` | The IDA Pro folder. Default: `ida_dir` in `exediff.ini`, then `IDADIR`, then the newest `IDA*` folder in Program Files. |

Exit codes: `0` written, `1` bad arguments, missing files or a refusal, `2` IDA failed. With `1` and `2` no database is written; `port-ida-database.log` and `port-ida-database.dump.json` may already be there when the refusal or failure came in a later step, and the log then says why. The output file only appears after every step succeeded.

## How long it takes

On the test fixture (the Trove sample pair, about 70,000 functions in IDA each, with the few annotations the test makes), a run took about half a minute plus the time to copy the databases: about 10 s to read the baseline, 10 s to read the old database, a few seconds to apply. A database with many annotations has not been measured: export, apply and the size of `port-ida-database.dump.json` grow with the number of annotated functions. `-Verify` adds the decompiler time for the functions it checks, on both sides.

## What is ported

Only your own annotations. A name, comment or type counts as yours when it differs from what IDA made of the same old exe on its own (exediff's cached analysis, the baseline). The comparison is exact text. Dummy names (`sub_`, `loc_`, `unk_`) are never copied. Without a baseline nothing can be compared: every function name IDA flags as user-made (RTTI and library names among them), every function comment and every local type is ported as if it were yours, with a warning; instruction comments, prototypes and data items are not ported at all; `-Strict` refuses such a run.

- Function names, function comments (plain and repeatable), and function folders.
- Local types, by name (never by ordinal).
- Instruction comments (plain, repeatable, anterior and posterior lines) and operand formats (hex, decimal, octal, binary, char, enum, struct offset).
- Function prototypes.
- Names, comments and types of data items that a ported function references.
- Hex-Rays edits: comments, number formats, union selections, collapsed blocks, and variable names, types and comments. Hex-Rays label names are listed under `hexrays-not-ported`, not ported.

Nothing is created in the new database: no functions, no data items where IDA has none. A name the new database already uses elsewhere is not applied (IDA refuses duplicates) and is listed. A name or comment that is already the same is left alone, so running the script again with `-NewDb <the output>` changes nothing.

## Classes of pairs

Each function of the old exe falls in one class, from `map.csv`:

| Class | When | What it gets |
|---|---|---|
| certain | same code (or only the called functions changed), paired as the only exact copy (`method` = `exact-unique`) | Everything, after a check that the shape is the same (see below). |
| likely | same code (or only the called functions changed), paired by any `method` other than `exact-unique`: one of several identical copies (`exact-group`), or told apart by the functions it calls or by a paired caller (`refined`, `propagated`), so the pair could be swapped | Nothing; listed under `not-ported-likely`. With `-IncludeLikely`: name, comments with the note `exediff: one of several identical functions`, folder. |
| changed | changed, at least `-MinSimilarity` percent similar | Name, comments with the note `exediff: changed vs <old exe> (NN% similar)`, folder, and instruction comments where a run of at least 3 instructions matches the old one in mnemonics, operand kinds, registers, displacements and immediates (addresses are left out). No prototypes, operand formats, data or Hex-Rays edits. |
| below | changed, under `-MinSimilarity` | Nothing; listed under `not-ported-below`. |
| unpaired | removed, or no pair found | Nothing; listed under `not-ported-unpaired`. |

The note is only added to functions that carry an annotation of yours. An older `exediff:` note is replaced, not added to.

The shape check for certain functions compares the mnemonics, operand kinds and frame sizes. In the code exediff compared, a certain function is the same code, so registers and constants are the same there too. IDA's function can be larger than the part exediff compared (for example extra chunks); in that extra code the check sees only the shape, so a different register or constant passes, and an enum or struct-offset format there can show another member. A function that fails the check is listed under `gate-failed` and gets no instruction data, prototype or Hex-Rays edits.

## Reading the log

`port-ida-database.log` starts with the files and options (and `note:` lines, see "Context check"), then three sections.

**Summary**: `ported` with a count per kind of your annotations; `made by this script` with the notes it added to changed and likely functions and the folders it created for your functions (these are not counted as ported); `listed` (the entries under Needs review, without `pseudo-differs`); `warnings`; and `mismatches` (the `pseudo-differs` entries, only with `-Verify`). "0 ported" with "the old database has no annotations of yours" means the old database only holds what IDA made itself; the output is then a plain copy of the new analysis. Without a baseline it says "nothing found that could be told apart from IDA's own" instead, because instruction data, prototypes and data items are then not looked at.

The console ends with the same counts in one line, `N ported, N listed for review, N warnings, ...`, and a line for the notes and folders made by the script when there are any. Above it, the console shows the context differences and up to 5 other warnings, then "N more warnings: see the log for the rest" when there are more.

**Warnings**: things that affect the whole run. The first lines are the context differences between the two databases (see below). Others: no baseline, no Hex-Rays, an image base that could not be checked, an input that is not a 64-bit x64 exe, or a value IDA did not keep.

**Needs review**: one group per category, `category (count)`, then one line per item with `[old 0x..., new 0x...]` (`-` when there is no address). A long group (more than 20 items) starts with a note on what to do with it. The categories:

| Category | Meaning |
|---|---|
| `not-ported-likely`, `not-ported-below`, `not-ported-unpaired` | The class of the function keeps it from being ported. |
| `no-old-function`, `no-new-function` | The address is not a function start in the old or in the new database. |
| `gate-failed` | A certain pair whose shape differs; it got names and comments only. |
| `name-in-use`, `new-has-name`, `name-refused` | The name is taken in the new database, the new function already has a name of its own, or IDA refused it. |
| `comment-differs` | The new function already has another comment. |
| `folder-not-ported`, `folder-missing`, `folder-differs`, `folder-refused` | A folder none of whose functions is ported, a function folder that could not be made, a function already in another folder, or a move IDA refused. |
| `type-differs`, `type-failed` | A local type of the same name differs, or does not parse. |
| `insn-not-ported`, `insn-skipped`, `insn-differs` | Instruction comments or formats left out: changed parts, formats on changed functions, or a different value already there. |
| `proto-not-ported`, `proto-skipped`, `proto-differs`, `proto-failed` | Prototypes left out, already different in the new database, or refused by IDA. |
| `data-not-ported`, `data-skipped`, `data-differs` | Data items left out, not found at the new address, or already different. |
| `hexrays-not-ported`, `hexrays-skipped`, `hexrays-differs`, `hexrays-failed` | Hex-Rays edits left out or not kept. |
| `pseudo-differs`, `pseudo-not-checked` | With `-Verify`: the first line where the pseudocode differs, or a function that could not be decompiled. |

## Context check

The old and new database are compared on their type libraries, compiler, ABI and bitness. A difference is a warning at the top of the Warnings and on the console. It is a real difference: types and prototypes can parse differently. Load the same type libraries in the new database (or remove the extra one) and run again. With `-Strict` any of these differences stops the run with exit code 1 before a database is written.

**Rebased databases are always refused.** `map.csv` uses each exe's own addresses, at the image base in its PE header. A database that was rebased (Edit > Segments > Rebase program, or IDA's debugger when ASLR loaded the module elsewhere, then saved) has every address shifted, so the pairs would point at the wrong functions, and a shift smaller than the code puts your names on other functions. So, with or without `-Strict`:

- the old database must have the image base of exediff's analysis of the old exe (without that analysis, the image base in the PE header of the old exe from `pair.txt`);
- the new database (the analysis, or `-NewDb`) must have the image base in the PE header of the new exe.

Otherwise the run stops with exit code 1, and no database is written, with "the old database was rebased from 0x... to 0x...: ... rebase it back to 0x... first". Rebase the database back (on a copy if you like) and run again. An exe's PE header is read from `input.exe` in exediff's work folder, else from the exe path in `pair.txt`, and only when the file has the md5 in `pair.txt`. When no such file can be read (and, for the old database, there is no analysis either), the image base is not checked: a warning on the console and in the log says so, and the run stops with exit code 1 when `-Strict` is given, or, for the new database, when `-NewDb` is given.

**Old and new image base**: when the new exe itself loads at another address than the old one, that is only information (a `note:` line in the log and on the console), not a warning, and `-Strict` does not stop for it.

## -Verify

Export decompiles every function that carries a prototype or Hex-Rays edits in a copy of the old database, and a third IDA pass decompiles the same functions in a copy of the finished output. The first differing line of each pair goes under `pseudo-differs`. Neither pass saves, so the guessed prototypes Hex-Rays stores while decompiling never reach a database.

An old database you worked in holds prototypes Hex-Rays guessed and stored whenever a function was decompiled; the new database has none. They change the pseudocode of the callers (`__int64 v13` against `__int64 *v13`). So before decompiling, the copy of the old database drops every function prototype that is neither yours (user-set) nor in the baseline. Without a baseline they stay, and more functions differ.

Stack frame member types are not ported, and Hex-Rays also retypes frame members when it decompiles. So a stack variable can be declared differently (`_BYTE v[4]` against `char v`) in a function that got everything else.

The comparison leaves out comments, so it does not check that ported Hex-Rays comments are there; their count is under Summary.

Mismatches are expected where the new code really does something else: a certain function can call changed functions, and code that IDA counts to the function but exediff did not compare can differ in registers and constants. A mismatch says "look here", not "the port is wrong". Without `-Verify` nothing is decompiled. If the verify pass itself fails in IDA, the whole run fails with exit code 2 and no database is written; run again without `-Verify`.

## Limits

- **Baseline.** Without exediff's cached analysis of the old exe, names, comments and local types are still ported, with a warning, but IDA's and yours cannot be told apart. Instruction data, prototypes and data items are then not exported at all. Run exediff with IDA first.
- Operand formats are ported to certain functions only. Changed functions get instruction comments only where their code still lines up with the old one.
- Hex-Rays collapsed blocks, variable settings and union selections need the whole function to match exactly, not only its shape. Hex-Rays label names are not ported, only listed: the decompiler numbers labels itself, and the numbers can shift in the new database.
- Data referenced only from other data, or only from changed functions, is listed under `data-not-ported`, not ported. So are names and comments on undefined bytes and on data inside a function.
- Each data item keeps at most 16 of its references (the lowest addresses); its new address is found through those.
- Hex-Rays merged-variable mappings (`lmaps`) are not ported, and neither are the names and types of stack frame members.
- Code labels inside functions (`loc_` renamed by you) and function flags are neither ported nor listed.
- If you renamed something IDA had already named (an RTTI `??_7...` name, a library name, an export), the new database holds IDA's name, so yours is listed under `new-has-name` or `data-differs`, not applied. A local type IDA made that you edited is listed under `type-differs`.
- The log, the dump and the temp folder `.port-ida-database.tmp` go into the folder of `-Output`. The default output is `output\` next to the script that runs, so `build\scripts\port-ida-database\output` when run from the build folder.
- `port-ida-database.dump.json` stays next to the output and can be large on a database with many annotations.
- The copy of the old database is always named `old.i64` in the temp folder.
- An existing output is replaced with `File.Replace`. Where that fails (for example on a drive without NTFS), the old output is deleted and the new one moved in its place; if that move fails, the finished database is left as `<output>.partial` and the run exits with code 2.
- The output database keeps the input path of the database it was copied from, `work\<hash>\input.exe`. IDA asks for the exe if it needs the file.
- Running the tool again on its own output (`-NewDb <output>`) is not supported for types the first run had to delete because they did not survive a round trip: the second run can leave IDA's own reading of such a type in place, with a warning and a `type-failed` line.
- Tested on x64 exes. DLLs and x86 files reach the tool untested (the console warns), and for x86 exediff finds function extents by heuristics, so the shape check fails more often and more code is left unchecked. Old `.idb` databases are untested.
