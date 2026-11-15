# Headless IDA: fast mode against full mode

IDA Pro 9.2, `idat.exe`, on `Trove_x64.new.exe` (21 MB). Tested 2026-11-13.

Default mode: full

## Timings

| Run | Wall time |
|---|---|
| Fast (`-a -c`, no auto-analysis), 10 functions | 12.2 s |
| Fast, the 60 functions of the real request | 6.6 s |
| Full, first run (auto-analysis of the whole exe) | 110–200 s per exe |
| Full, later runs opening the saved `.i64`, 60 functions | 5–6 s per exe |

`exediff.exe` on the sample pair: 242 s on the first run (both exes analysed one after the other), 16 s on later runs.

## Fast against full

On the 60 functions of the real request, fast mode gives the same text for 42. Most of the other 18 differ only in how data is typed (`&off_X` against `off_X`, `&unk_X` against a string literal or a name such as `Block`, `void *` against `char *`). Three differ in substance:

- `sub_140287E50`: a call without its argument (`sub_1400C0CC0()` against `sub_1400C0CC0((AK::MusicEngine *)a1)`).
- `sub_1406D3F40`: wrong return type (`__int64` and `return new_1406D27A0(a1)` against `void`, the FLIRT name `_DeleteExceptionPtr`).
- `sub_1406D27A0`: integer widths (`__int64` against `int`).

In the first spike (10 functions), fast mode also showed undefined callees as casts (`((void (__fastcall *)(...))unk_140F95134)(a1, 360)`). Defining every requested callee as a function first (`add_func` at each `N` address) removed those casts. Full mode wins: three of 60 is above the one-in-ten limit, and full analysis also brings FLIRT and RTTI names. Later runs reuse the database, so it costs time only on the first run per exe.

## What had to be fixed

- **Chunks that touch.** `.pdata` splits one body into ranges that touch, for example `sub_1404E28B0` (main range `4E28B0`–`4E28C7`, then chunks up to `4E3E0C`). Full analysis made a 3-byte function out of it, and decompiling failed with code -13. `add_func` over the merged range returns False while the old function exists. The retry that works: merge touching chunks into the main range, delete every function inside the range, `del_items`, `create_insn` across the range, then `add_func(start, merged_end)`, `append_func_tail` for chunks that don't touch, then `reanalyze_function` and `plan_and_wait`. Without the reanalysis Hex-Rays reports "bad sp value" and invents 42 arguments. On the sample pair 3 old and 2 new functions need this retry, and all of them then decompile.
- **The saved database changes the output.** Hex-Rays stores the prototypes it guesses for functions it has decompiled, so a second run printed different calls and types for 12 of 60 functions (for example `sub_140783710()` against `sub_140783710((_QWORD *)a1)`). Now `ida/analyse.py` saves the database once after auto-analysis, `decompile.py` sets `ABANDON_DATABASE=YES` so it never saves, and it decompiles every requested function twice, writing out only the second pass. Two runs now give identical files.
- **Names.** `set_name(ea, "sub_140228B70")` at another address returns True, but IDA keeps showing its own dummy name. The script checks `get_name` afterwards and otherwise sets `exediff_<name>`, then maps it back in the written text.
- **Stack slots.** Declaration comments such as `// [rsp+20h] [rbp-48h]` change for every variable when the frame grows. `normalize_c` drops them.

## Commands that work

```
idat.exe -A -c -L"<side>\ida.log" -S"\"ida\analyse.py\"" "<side>\input.exe"
idat.exe -A -L"<side>\ida.log" -S"\"ida\decompile.py\" \"<side>\request.txt\" \"<side>\out\" full" "<side>\input.exe.i64"
idat.exe -A -a -c -L"<side>\ida.log" -S"\"ida\decompile.py\" \"<side>\request.txt\" \"<side>\out\" fast" "<side>\input.exe"
```

IDA 9.2 names the database `input.exe.i64`. `ABANDON_DATABASE=YES` (set from the script with `idc.process_config_line`) leaves an existing `.i64` untouched. A `save_database` call made in a session that then abandons is lost. The "Could not find platform dependent libraries" line on stderr is harmless.
