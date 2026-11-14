# Changelog

## 1.0.0

First release.

- Pure-Python ELF parser (32/64-bit, both endiannesses); never executes or loads the inspected file
- Checks PIE, NX, RELRO, stack canary, FORTIFY, RPATH/RUNPATH, text relocations, RWX segments, stripped, setuid bits
- Directory mode without following symlinks, `--json`, `--only-failing`, size caps
