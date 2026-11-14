# elfcheck

**See which binaries lack basic exploit mitigations, without running them.** Hardening flags (PIE, NX, RELRO, stack canary, FORTIFY) are
easy to lose in a build and tedious to check by hand. elfcheck parses ELF files with pure Python `struct`, in 32 or 64-bit and either byte
order, and reports a checksec-style table. It only reads the file: it never executes, loads, or passes it to another program.

Real output on three synthetic ELF files (built in memory by the test helper) plus a text file:

```
$ elfcheck .
FILE        BITS  PIE  NX   RELRO    CANARY  FORTIFY  RPATH  RUNPATH  TEXTREL  RWX  STRIPPED  SETUID
./hardened  64    yes  yes  full     yes     yes      -      -        -        -    yes       -
./legacy    64    no   NO   none     NO      no       -      RISKY    YES      -    yes       -
./partial   64    yes  yes  partial  yes     no       set    -        -        -    yes       -
$ echo $?
1
```

`notes.txt` in that directory was skipped silently (directory mode skips non-ELF by magic). `--json` gives every check with a status
(`pass`, `fail`, `warn`, `info`, `na`) and a detail string.

## Usage

```
elfcheck PATH [PATH ...] [--json] [--only-failing] [--max-size BYTES]
```

- A directory is walked recursively; symlinks (files and directories) are not followed. A symlink given explicitly is refused.
- `--only-failing` hides files with no failing check. `--max-size` (default 64 MiB) skips bigger files, listed under "skipped".
- Checks: PIE (`DT_FLAGS_1` PIE, or `ET_DYN` with an interpreter), NX (`PT_GNU_STACK` present and not executable), RELRO (`PT_GNU_RELRO`, full
  if `BIND_NOW`), canary (`__stack_chk_fail`/`__stack_chk_guard` symbol), FORTIFY (`__*_chk` symbols), RPATH/RUNPATH (flags relative,
  empty, `$ORIGIN/..` and writable-looking paths such as `/tmp`, `/home`), text relocations, writable+executable LOAD segments,
  stripped (info), setuid/setgid bit (info, from file mode).
- A shared library with no interpreter shows PIE as `dso` (not a failure).

## Exit codes

`0` nothing failing, `1` at least one failing check (or a malformed ELF found while walking a directory), `2` usage or input error (missing
path, a single file that is not ELF or is malformed or unreadable).

## Limits

- It looks at what the file declares, not at what the code does. A canary or FORTIFY result is inferred from imported or defined symbol names;
  a binary that statically links its own checks, or has no fortifiable calls, can show `no` for FORTIFY without being weak.
- Symbol counting for binaries without section headers uses `DT_HASH` or the gap between `DT_SYMTAB` and `DT_STRTAB`; `DT_GNU_HASH`-only
  binaries with stripped section headers may show canary/fortify as `no` or `n/a` when the heuristic cannot size the table.
- Statically linked binaries have no dynamic section, so RELRO "full" cannot be confirmed and canary relies on `.symtab` if present.
- No checks for CET/IBT/shadow stack, ASLR of the running system, seccomp, or capabilities. No other formats (Mach-O, PE).
- Fixed caps (4096 program headers, 4096 sections, 200000 symbols) protect against hostile files; very odd but valid files beyond them are
  reported as malformed.
- Tested on synthetic files only; not validated against binaries from every toolchain.

MIT licensed.
