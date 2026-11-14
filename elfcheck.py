#!/usr/bin/env python3
"""elfcheck: checksec-style hardening checker for ELF files.

Pure standard library. The file is only read and parsed with ``struct``; it is
never executed, loaded, or passed to another program.

Exit codes: 0 clean, 1 findings, 2 usage/input error.
"""
import argparse
import json
import os
import stat
import struct
import sys

__version__ = "1.0.0"

DEFAULT_MAX_SIZE = 64 * 1024 * 1024
MAX_PHNUM = 4096
MAX_SHNUM = 4096
MAX_DYN_ENTRIES = 4096
MAX_SYMS = 200000
MAX_NAME = 512

ET_EXEC, ET_DYN = 2, 3
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 3, 0x6474E551, 0x6474E552
PF_X, PF_W = 1, 2
DT_NULL, DT_HASH, DT_STRTAB, DT_SYMTAB = 0, 4, 5, 6
DT_SYMENT, DT_TEXTREL, DT_RPATH, DT_BIND_NOW = 11, 22, 15, 24
DT_RUNPATH, DT_FLAGS, DT_FLAGS_1 = 29, 30, 0x6FFFFFFB
DF_TEXTREL, DF_BIND_NOW = 0x4, 0x8
DF_1_NOW, DF_1_PIE = 0x1, 0x08000000
SHT_SYMTAB, SHT_DYNSYM = 2, 11

CHECKS = ["pie", "nx", "relro", "canary", "fortify", "rpath", "runpath",
          "textrel", "rwx", "stripped", "setuid"]

WRITABLE_PREFIXES = ("/tmp", "/var/tmp", "/dev/shm", "/run/user", "/home", "/Users", "/var/crash")
VAR_PREFIXES = ("$ORIGIN", "${ORIGIN}", "$LIB", "${LIB}", "$PLATFORM", "${PLATFORM}")


class ElfError(Exception):
    """Raised for files that claim to be ELF but are truncated or malformed."""


class NotElf(Exception):
    pass


def clean(text):
    """Make text safe for terminals: escape control and non-ASCII characters."""
    out = []
    for ch in str(text):
        o = ord(ch)
        if 32 <= o < 127:
            out.append(ch)
        else:
            out.append("\\x%02x" % o if o < 256 else "\\u%04x" % o)
    return "".join(out)


def chk(status, detail=""):
    return {"status": status, "detail": detail}


class Elf:
    def __init__(self, data):
        self.d = data
        if len(data) < 16 or data[:4] != b"\x7fELF":
            raise NotElf("not an ELF file")
        cls, enc = data[4], data[5]
        if cls not in (1, 2):
            raise ElfError("invalid ELF class %d" % cls)
        if enc not in (1, 2):
            raise ElfError("invalid ELF data encoding %d" % enc)
        self.bits = 32 if cls == 1 else 64
        self.e = "<" if enc == 1 else ">"
        self.endian = "little" if enc == 1 else "big"
        self.word = 4 if self.bits == 32 else 8
        self._header()
        self.phdrs = self._program_headers()
        self.sections = self._sections()

    def u(self, fmt, off):
        f = self.e + fmt
        size = struct.calcsize(f)
        if off < 0 or off + size > len(self.d):
            raise ElfError("truncated file (read at offset %d)" % off)
        return struct.unpack_from(f, self.d, off)

    def _header(self):
        if self.bits == 32:
            fmt, base = "HHIIIIIHHHHHH", 16
            (self.type, self.machine, _v, self.entry, self.phoff, self.shoff, _fl,
             _eh, self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx) = self.u(fmt, base)
        else:
            fmt, base = "HHIQQQIHHHHHH", 16
            (self.type, self.machine, _v, self.entry, self.phoff, self.shoff, _fl,
             _eh, self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx) = self.u(fmt, base)

    def _program_headers(self):
        out = []
        if self.phnum == 0:
            return out
        need = 32 if self.bits == 32 else 56
        if self.phentsize < need:
            raise ElfError("program header entry size %d too small" % self.phentsize)
        if self.phnum > MAX_PHNUM:
            raise ElfError("too many program headers (%d)" % self.phnum)
        if self.phoff + self.phnum * self.phentsize > len(self.d):
            raise ElfError("program header table extends past end of file")
        for i in range(self.phnum):
            o = self.phoff + i * self.phentsize
            if self.bits == 32:
                t, off, va, _pa, fsz, msz, fl, _al = self.u("IIIIIIII", o)
            else:
                t, fl, off, va, _pa, fsz, msz, _al = self.u("IIQQQQQQ", o)
            out.append({"type": t, "flags": fl, "offset": off, "vaddr": va, "filesz": fsz, "memsz": msz})
        return out

    def _sections(self):
        """Section headers are optional; any problem just means 'no sections'."""
        out = []
        need = 40 if self.bits == 32 else 64
        if self.shoff == 0 or self.shnum == 0 or self.shentsize < need or self.shnum > MAX_SHNUM:
            return out
        if self.shoff + self.shnum * self.shentsize > len(self.d):
            return out
        for i in range(self.shnum):
            o = self.shoff + i * self.shentsize
            if self.bits == 32:
                _n, t, _f, _a, off, sz, link, _i, _al, ent = self.u("IIIIIIIIII", o)
            else:
                _n, t, _f, _a, off, sz, link, _i, _al, ent = self.u("IIQQQQIIQQ", o)
            out.append({"type": t, "offset": off, "size": sz, "link": link, "entsize": ent})
        return out

    def v2o(self, vaddr):
        for p in self.phdrs:
            if p["type"] == PT_LOAD and p["vaddr"] <= vaddr < p["vaddr"] + p["filesz"]:
                off = p["offset"] + (vaddr - p["vaddr"])
                if off < len(self.d):
                    return off
        return None

    def dynamic(self):
        """Return list of (tag, value) from PT_DYNAMIC, or None when absent."""
        seg = next((p for p in self.phdrs if p["type"] == PT_DYNAMIC), None)
        if seg is None:
            return None
        out = []
        fmt = "II" if self.bits == 32 else "qQ"
        esz = 2 * self.word
        off = seg["offset"]
        end = min(off + seg["filesz"], len(self.d))
        for _ in range(MAX_DYN_ENTRIES):
            if off + esz > end:
                break
            tag, val = self.u(fmt, off)
            if tag == DT_NULL:
                break
            out.append((tag, val))
            off += esz
        return out

    def cstr(self, base, idx, limit_end):
        start = base + idx
        if start < 0 or start >= len(self.d):
            return None
        end = min(len(self.d), limit_end if limit_end else len(self.d), start + MAX_NAME)
        nul = self.d.find(b"\0", start, end)
        return self.d[start:nul if nul >= 0 else end]

    def _read_syms(self, off, size, ent, stroff, strsize):
        names = []
        symsz = 16 if self.bits == 32 else 24
        ent = ent if ent >= symsz else symsz
        count = min(size // ent, MAX_SYMS)
        for i in range(count):
            o = off + i * ent
            if o + symsz > len(self.d):
                break
            nameoff = struct.unpack_from(self.e + "I", self.d, o)[0]
            if nameoff == 0 or nameoff >= strsize:
                continue
            s = self.cstr(stroff, nameoff, stroff + strsize)
            if s:
                names.append(s)
        return names

    def symbols(self, dyn):
        """Return (names, have_symbol_source, has_symtab)."""
        names = []
        have = False
        has_symtab = any(s["type"] == SHT_SYMTAB for s in self.sections)
        for s in self.sections:
            if s["type"] in (SHT_DYNSYM, SHT_SYMTAB) and 0 <= s["link"] < len(self.sections):
                st = self.sections[s["link"]]
                if s["offset"] + s["size"] <= len(self.d) and st["offset"] + st["size"] <= len(self.d):
                    have = True
                    names += self._read_syms(s["offset"], s["size"], s["entsize"], st["offset"], st["size"])
        if not have and dyn is not None:
            d = dict()
            for t, v in dyn:
                d.setdefault(t, v)
            if DT_SYMTAB in d and DT_STRTAB in d:
                so, to = self.v2o(d[DT_SYMTAB]), self.v2o(d[DT_STRTAB])
                if so is not None and to is not None:
                    symsz = 16 if self.bits == 32 else 24
                    n = None
                    if DT_HASH in d:
                        ho = self.v2o(d[DT_HASH])
                        if ho is not None and ho + 8 <= len(self.d):
                            n = struct.unpack_from(self.e + "II", self.d, ho)[1]
                    if n is None and to > so:
                        n = (to - so) // symsz
                    if n:
                        n = min(n, MAX_SYMS)
                        strsize = len(self.d) - to
                        have = True
                        names += self._read_syms(so, n * symsz, symsz, to, strsize)
        return names, have, has_symtab


def split_paths(s):
    return s.split(":") if s != "" else [""]


def path_issues(paths):
    issues = []
    for p in paths:
        if p == "" or p == ".":
            issues.append("empty/'.' entry means current directory")
        elif p.startswith(VAR_PREFIXES):
            rest = p
            for v in VAR_PREFIXES:
                if p.startswith(v):
                    rest = p[len(v):]
                    break
            if ".." in rest.split("/"):
                issues.append("%s climbs with '..'" % clean(p))
        elif not p.startswith("/"):
            issues.append("relative path %s" % clean(p))
        elif p.startswith(WRITABLE_PREFIXES):
            issues.append("writable-looking path %s" % clean(p))
    return issues


def analyze_bytes(data, mode=None):
    elf = Elf(data)
    dyn = elf.dynamic()
    dmap = {}
    for t, v in (dyn or []):
        dmap.setdefault(t, v)
    flags = dmap.get(DT_FLAGS, 0)
    flags1 = dmap.get(DT_FLAGS_1, 0)
    has_interp = any(p["type"] == PT_INTERP for p in elf.phdrs)
    gstack = next((p for p in elf.phdrs if p["type"] == PT_GNU_STACK), None)
    relro = any(p["type"] == PT_GNU_RELRO for p in elf.phdrs)
    now = bool(DT_BIND_NOW in dmap or flags & DF_BIND_NOW or flags1 & DF_1_NOW)
    c = {}

    # PIE
    if elf.type == ET_DYN:
        if flags1 & DF_1_PIE:
            c["pie"] = chk("pass", "PIE (DT_FLAGS_1)")
        elif has_interp:
            c["pie"] = chk("pass", "PIE (ET_DYN with interpreter)")
        else:
            c["pie"] = chk("info", "shared object (DSO), not an executable")
    elif elf.type == ET_EXEC:
        c["pie"] = chk("fail", "no PIE (ET_EXEC, fixed load address)")
    else:
        c["pie"] = chk("info", "ELF type %d" % elf.type)

    # NX / executable stack
    if gstack is None:
        c["nx"] = chk("fail", "no PT_GNU_STACK (stack assumed executable)")
    elif gstack["flags"] & PF_X:
        c["nx"] = chk("fail", "executable stack (PT_GNU_STACK has X)")
    else:
        c["nx"] = chk("pass", "NX enabled")

    # RELRO
    if relro and now:
        c["relro"] = chk("pass", "full RELRO")
    elif relro:
        c["relro"] = chk("warn", "partial RELRO")
    else:
        c["relro"] = chk("fail", "no RELRO")

    # symbols
    names, have_syms, has_symtab = elf.symbols(dyn)
    nameset = set(names)
    if not have_syms:
        c["canary"] = chk("na", "no symbol table available")
        c["fortify"] = chk("na", "no symbol table available")
    else:
        if b"__stack_chk_fail" in nameset or b"__stack_chk_guard" in nameset:
            c["canary"] = chk("pass", "stack protector symbol present")
        else:
            c["canary"] = chk("fail", "no __stack_chk_fail")
        fort = sorted(n for n in nameset if n.startswith(b"__") and n.endswith(b"_chk")
                      and n not in (b"__stack_chk_fail", b"__chk_fail") and len(n) > 6)
        if fort:
            c["fortify"] = chk("pass", "%d fortified function(s): %s" % (
                len(fort), ", ".join(clean(f.decode("latin-1")) for f in fort[:5])))
        else:
            c["fortify"] = chk("fail", "no *_chk symbols")

    # RPATH / RUNPATH
    strtab = None
    strsz = dmap.get(10)
    if DT_STRTAB in dmap:
        so = elf.v2o(dmap[DT_STRTAB])
        if so is not None:
            strtab = so
    for key, tag in (("rpath", DT_RPATH), ("runpath", DT_RUNPATH)):
        if tag not in dmap:
            c[key] = chk("pass", "none")
            continue
        s = None
        if strtab is not None:
            end = strtab + strsz if strsz else None
            raw = elf.cstr(strtab, dmap[tag], end)
            if raw is not None:
                s = raw.decode("latin-1")
        if s is None:
            c[key] = chk("warn", "present but unreadable")
            continue
        issues = path_issues(split_paths(s))
        if issues:
            c[key] = chk("fail", "%s (%s)" % (clean(s), "; ".join(issues)))
        else:
            c[key] = chk("info", clean(s))

    # text relocations
    if DT_TEXTREL in dmap or flags & DF_TEXTREL:
        c["textrel"] = chk("fail", "DT_TEXTREL present")
    else:
        c["textrel"] = chk("pass", "none")

    # RWX load segments
    rwx = [p for p in elf.phdrs if p["type"] == PT_LOAD and p["flags"] & PF_X and p["flags"] & PF_W]
    c["rwx"] = chk("fail", "%d writable+executable LOAD segment(s)" % len(rwx)) if rwx else chk("pass", "none")

    c["stripped"] = chk("info", "not stripped (.symtab present)" if has_symtab else "stripped (no .symtab)")
    c["setuid"] = chk("pass", "n/a")
    return {
        "bits": elf.bits, "endian": elf.endian, "type": elf.type, "machine": elf.machine,
        "dynamic": dyn is not None, "checks": c,
    }


def read_limited(path, max_size):
    """Read a regular file without following symlinks. Returns (data, mode) or raises."""
    flags = os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("not a regular file")
        if st.st_size > max_size:
            return None, st.st_mode
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(max_size + 1)
        if len(data) > max_size:
            return None, st.st_mode
        return data, st.st_mode
    finally:
        os.close(fd)


def check_file(path, max_size=DEFAULT_MAX_SIZE):
    """Return a result dict. result['error'] set for malformed, ['skipped'] for large/non-ELF."""
    res = {"path": clean(path)}
    try:
        data, mode = read_limited(path, max_size)
    except OSError as exc:
        res["error"] = "cannot read: %s" % clean(exc.strerror or exc)
        return res
    if data is None:
        res["skipped"] = "larger than size cap (%d bytes)" % max_size
        return res
    try:
        info = analyze_bytes(data)
    except NotElf:
        res["skipped"] = "not an ELF file"
        return res
    except (ElfError, struct.error) as exc:
        res["error"] = "malformed ELF: %s" % clean(exc)
        return res
    res.update(info)
    if mode & stat.S_ISUID or mode & stat.S_ISGID:
        kind = "setuid" if mode & stat.S_ISUID else "setgid"
        res["checks"]["setuid"] = chk("info", "%s bit set (mode %o)" % (kind, mode & 0o7777))
    res["failing"] = sorted(k for k, v in res["checks"].items() if v["status"] == "fail")
    return res


def iter_targets(paths):
    for p in paths:
        try:
            lst = os.lstat(p)
        except OSError as exc:
            yield p, False, exc
            continue
        if stat.S_ISDIR(lst.st_mode):
            for root, dirs, files in os.walk(p, followlinks=False):
                dirs.sort()
                for f in sorted(files):
                    fp = os.path.join(root, f)
                    try:
                        if not stat.S_ISREG(os.lstat(fp).st_mode):
                            continue
                    except OSError:
                        continue
                    yield fp, True, None
        else:
            yield p, False, None


def short(r, check):
    v = r["checks"][check]
    s = v["status"]
    if check == "pie":
        return {"pass": "yes", "fail": "no", "info": "dso"}.get(s, s)
    if check == "nx":
        return "yes" if s == "pass" else "NO"
    if check == "relro":
        return {"pass": "full", "warn": "partial", "fail": "none"}[s]
    if check in ("canary",):
        return {"pass": "yes", "fail": "NO", "na": "n/a"}[s]
    if check == "fortify":
        return {"pass": "yes", "fail": "no", "na": "n/a"}[s]
    if check in ("rpath", "runpath"):
        return {"pass": "-", "info": "set", "fail": "RISKY", "warn": "?"}[s]
    if check == "textrel":
        return "YES" if s == "fail" else "-"
    if check == "rwx":
        return "YES" if s == "fail" else "-"
    if check == "stripped":
        return "yes" if v["detail"].startswith("stripped") else "no"
    if check == "setuid":
        return "SUID" if s == "info" else "-"
    return s


def render_table(results, only_failing):
    cols = ["pie", "nx", "relro", "canary", "fortify", "rpath", "runpath", "textrel", "rwx", "stripped", "setuid"]
    rows = []
    for r in results:
        if "checks" in r:
            if only_failing and not r["failing"]:
                continue
            rows.append([r["path"], str(r["bits"])] + [short(r, c) for c in cols])
        elif "error" in r:
            rows.append([r["path"], "ERROR: " + r["error"]])
    if not rows:
        return "(no ELF files to report)"
    head = ["FILE", "BITS"] + [c.upper() for c in cols]
    full = [r for r in rows if len(r) > 2]
    widths = [len(h) for h in head]
    for r in full:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(head)).rstrip()]
    for r in rows:
        if len(r) > 2:
            lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(r)).rstrip())
        else:
            lines.append("  ".join(r))
    return "\n".join(lines)


def build_parser():
    p = argparse.ArgumentParser(
        prog="elfcheck",
        description="checksec-style hardening checker for ELF files. Reads and parses only; never executes.",
        epilog="Exit codes: 0 clean, 1 findings, 2 usage/input error.")
    p.add_argument("paths", nargs="+", help="ELF file(s) or directories (walked without following symlinks)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--only-failing", action="store_true", help="show only files with at least one failing check")
    p.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE,
                   help="skip files larger than this many bytes (default %d)" % DEFAULT_MAX_SIZE)
    p.add_argument("--version", action="version", version="elfcheck " + __version__)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.max_size < 64:
        print("elfcheck: --max-size too small", file=sys.stderr)
        return 2
    results, skipped, input_error = [], [], False
    for path, from_dir, err in iter_targets(args.paths):
        if err is not None:
            print("elfcheck: cannot access %s: %s" % (clean(path), clean(err.strerror or err)), file=sys.stderr)
            input_error = True
            continue
        r = check_file(path, args.max_size)
        if "skipped" in r:
            if from_dir and r["skipped"] == "not an ELF file":
                continue  # quietly skip non-ELF files found while walking
            if not from_dir and r["skipped"] == "not an ELF file":
                print("elfcheck: %s: not an ELF file" % r["path"], file=sys.stderr)
                input_error = True
                continue
            skipped.append(r)
            continue
        if "error" in r:
            if not from_dir:
                print("elfcheck: %s: %s" % (r["path"], r["error"]), file=sys.stderr)
                input_error = True
                continue
        results.append(r)
    findings = any(r.get("failing") or "error" in r for r in results)
    if args.json:
        shown = [r for r in results if not (args.only_failing and "checks" in r and not r["failing"])]
        print(json.dumps({"version": __version__, "results": shown, "skipped": skipped,
                          "findings": findings}, indent=2, sort_keys=True))
    else:
        print(render_table(results, args.only_failing))
        for s in skipped:
            print("skipped: %s (%s)" % (s["path"], s["skipped"]))
    if input_error:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
