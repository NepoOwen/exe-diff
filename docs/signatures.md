# Signatures

Every function the report lists (changed, added or removed) gets the code signature that Signature Maker (A200K, `SigMaker9_64.dll`, v1.0.10) would make for it with "Create unique signature for current code address". The report shows the old and new signature as a `-`/`+` pair, and for changed and removed functions where the old signature lands in the new exe.

## Options

These are the options from the owner's dialog (2026-11-13):

| Option | Value |
|---|---|
| Action | Create unique signature for current code address |
| Output format | IDA Signature (`E8 ? ? ? ? 45 33`) |
| Wildcards for operands | on |
| Continue when leaving function scope | on (the plugin's default is off) |
| Wildcard optimized / combined instructions | on |
| Do not wildcard 0-Operands | on |
| Operand types | plugin default for x86: every type except `o_reg` |
| Maximum single signature length | 1000 bytes (plugin default) |

## Why the plugin itself isn't called

The plugin can't run headless:
- its only entry point is a modal `ask_form`;
- it reads the address from `get_screen_ea()`, which is `BADADDR` under `idat -A`, even from a `ready_to_run` hook;
- it has no IDC or Python API, and `run()` ignores its argument.

Probing it on a copy of the database printed `Error: Invalid address` for every function. Running it would need a GUI IDA instance, which exediff never starts.

`ida/decompile.py` (`wildcards`, `Haystack`, `signature`) reimplements the plugin's algorithm instead, from its v1.0.10 source (`Main.cpp`: `GetOperandWildcardBits`, `GenerateUniqueSignatureForEA`; `SignatureUtils.cpp`: `TrimSignature`, `BuildIDASignatureString`):
- **Decoding.** It decodes with IDA's own `decode_insn`, so operand types and `offb` are the same values the plugin sees.
- **Operand bytes.** An operand's wildcard runs from `offb` up to the next operand's `offb`, when that operand exists and has `offb > 0`, or otherwise to the end of the instruction.
- **Exceptions.** `o_imm` with value 0 stays literal. Operands encoded in the opcode (`offb == 0`) wildcard the whole instruction, which also covers `int 3` padding.
- **Uniqueness.** It checks after every instruction, over the bytes of every segment in the database.
- **Trimming.** Trailing wildcards are removed at the end.

## Differences from the plugin

- **Over 1000 bytes:** the plugin asks "Signature is already at N bytes. Continue?"; here the function gets an error instead ("Signature not unique after 1000 bytes").
- **Segments:** with AVX2, the plugin's scan joins all segments into one buffer, so a match could in theory span two segments. Here each segment is searched on its own.

## Functions without a signature

On old vs pts, about 2,060 functions per side get "Signature not unique after 1000 bytes, N places match".
- **Which functions.** They are mostly static-initializer functions (`sub rsp, 28h; xor eax, eax; lea rdx, [rsp+..]; ... call ...`) that sit next to each other in `.text`.
- **Why.** With every operand type but registers wildcarded, 885 of them have identical code. Even past the function end the following ones are identical too, so 1000 bytes still match in 885 places.
- **The plugin.** The plugin with the same options gives the same result, or asks to continue past 1000 bytes. These need a signature from an xref instead ("Find shortest XREF signature"), which this tool doesn't make.

## Speed

Matches can only drop as the signature grows. The search therefore checks instructions in batches that double up to 64, and steps through one instruction at a time only once a batch is unique. The output is identical to checking after every instruction, verified on 536 functions.

On the 200 failing functions tested, this took the time from about 42 s to 6.7 s. On old vs pts (8,119 and 8,697 functions), the IDA step per side went from 611 s to 402 s and from 644 s to 437 s, about half of it the decompiler's first pass. The signatures were identical to the unbatched run, except that two "reached end of executable code" errors now also give the match count.

## Checks

- Each generated signature was searched again with pefile across the PE sections. On the sample pair, all 73 (36 old, 37 new) have exactly one hit, at the function start.
- Nobody has compared the output against the plugin running in a GUI yet. To spot-check, open the old exe in IDA, go to `0x14028D0B0` and run the plugin with the options above. The expected result is `85 D2 0F 85 ? ? ? ? 53 48 83 EC ? 0F 29 7C 24`.

## Files

- `build\work\<hash>\out\<rva>.sig`: the signature, or `error: <reason>`.
- `src/sig/scan`: parses an IDA signature and searches a PE image, used for "the old signature finds ... in the new exe".
