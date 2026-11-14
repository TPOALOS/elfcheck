import contextlib
import io
import json
import os
import stat
import struct
import tempfile
import unittest

import elfcheck as ec


def build_elf(bits=64, endian="<", etype=3, interp=True, gnu_stack=0b110, relro=False,
              dyn_extra=(), syms=(), rpath=None, runpath=None, sections=False,
              symtab_names=None, load_flags=0b101, dynamic=True, hash_table=False, dyn_in_seg=True):
    """Build a tiny synthetic ELF. One PT_LOAD maps the whole file with vaddr == offset."""
    w = 4 if bits == 32 else 8
    ehsize = 52 if bits == 32 else 64
    phsize = 32 if bits == 32 else 56
    phs = [("load", None)]
    if interp:
        phs.append(("interp", None))
    if dynamic:
        phs.append(("dyn", None))
    if gnu_stack is not None:
        phs.append(("stack", gnu_stack))
    if relro:
        phs.append(("relro", None))
    body_start = ehsize + phsize * len(phs)
    symsz = 16 if bits == 32 else 24

    strtab = bytearray(b"\0")

    def addstr(s):
        off = len(strtab)
        strtab.extend(s + b"\0")
        return off

    name_offs = [addstr(s) for s in syms]
    rp = addstr(rpath) if rpath is not None else None
    rn = addstr(runpath) if runpath is not None else None
    nsyms = 1 + len(syms)
    dynsym_off = body_start
    dynsym = bytearray(symsz)
    for no in name_offs:
        if bits == 32:
            dynsym += struct.pack(endian + "IIIBBH", no, 0, 0, 0x12, 0, 0)
        else:
            dynsym += struct.pack(endian + "IBBHQQ", no, 0x12, 0, 0, 0, 0)
    dynstr_off = dynsym_off + len(dynsym)
    pos = dynstr_off + len(strtab)
    hash_off = None
    hash_blob = b""
    if hash_table:
        hash_off = pos
        hash_blob = struct.pack(endian + "II", 1, nsyms) + struct.pack(endian + "II", 0, 0)
        pos += len(hash_blob)
    dyn_off = pos
    tags = [(5, dynstr_off), (6, dynsym_off), (10, len(strtab))]
    if hash_off is not None:
        tags.append((4, hash_off))
    if rp is not None:
        tags.append((15, rp))
    if rn is not None:
        tags.append((29, rn))
    tags += list(dyn_extra)
    tags.append((0, 0))
    dfmt = endian + ("II" if bits == 32 else "qQ")
    dyn_blob = b"".join(struct.pack(dfmt, t, v) for t, v in tags) if dynamic else b""
    pos = dyn_off + len(dyn_blob)

    extra = b""
    shdrs = b""
    shnum = 0
    shoff = 0
    if sections:
        sym_strtab = bytearray(b"\0")
        sym_blob = bytearray(symsz)
        for n in (symtab_names or []):
            no = len(sym_strtab)
            sym_strtab += n + b"\0"
            if bits == 32:
                sym_blob += struct.pack(endian + "IIIBBH", no, 0, 0, 0x12, 0, 0)
            else:
                sym_blob += struct.pack(endian + "IBBHQQ", no, 0x12, 0, 0, 0, 0)
        symtab_off = pos
        symstr_off = symtab_off + len(sym_blob)
        extra = bytes(sym_blob) + bytes(sym_strtab)
        pos = symstr_off + len(sym_strtab)
        shoff = pos

        def sh(t, off, size, link, ent):
            if bits == 32:
                return struct.pack(endian + "IIIIIIIIII", 0, t, 0, 0, off, size, link, 0, 1, ent)
            return struct.pack(endian + "IIQQQQIIQQ", 0, t, 0, 0, off, size, link, 0, 1, ent)

        sl = [sh(0, 0, 0, 0, 0),
              sh(11, dynsym_off, len(dynsym), 2, symsz),
              sh(3, dynstr_off, len(strtab), 0, 0)]
        if symtab_names is not None:
            sl += [sh(2, symtab_off, len(sym_blob), 4, symsz), sh(3, symstr_off, len(sym_strtab), 0, 0)]
        shdrs = b"".join(sl)
        shnum = len(sl)

    total = pos + len(shdrs)

    def ph(kind, flags):
        if kind == "load":
            t, off, sz, fl = 1, 0, total, load_flags
        elif kind == "interp":
            t, off, sz, fl = 3, 0, 0, 4
        elif kind == "dyn":
            t, off, sz, fl = 2, dyn_off, (len(dyn_blob) if dyn_in_seg else 0), 6
        elif kind == "stack":
            t, off, sz, fl = 0x6474E551, 0, 0, flags
        else:
            t, off, sz, fl = 0x6474E552, 0, 0, 4
        va = off
        if bits == 32:
            return struct.pack(endian + "IIIIIIII", t, off, va, va, sz, sz, fl, 1)
        return struct.pack(endian + "IIQQQQQQ", t, fl, off, va, va, sz, sz, 1)

    phdrs = b"".join(ph(k, f) for k, f in phs)
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if endian == "<" else 2, 1]) + b"\0" * 9
    if bits == 32:
        hdr = struct.pack(endian + "HHIIIIIHHHHHH", etype, 3, 1, 0x1000, ehsize, shoff, 0,
                          ehsize, phsize, len(phs), 40, shnum, 0)
    else:
        hdr = struct.pack(endian + "HHIQQQIHHHHHH", etype, 62, 1, 0x1000, ehsize, shoff, 0,
                          ehsize, phsize, len(phs), 64, shnum, 0)
    blob = ident + hdr + phdrs + bytes(dynsym) + bytes(strtab) + hash_blob + dyn_blob + extra + shdrs
    assert len(blob) == total
    return blob


def run_checks(data):
    return ec.analyze_bytes(data)["checks"]


def st(data, name):
    return run_checks(data)[name]["status"]


class TestPie(unittest.TestCase):
    def test_pie_via_flags1(self):
        d = build_elf(interp=False, dyn_extra=[(ec.DT_FLAGS_1, ec.DF_1_PIE)])
        self.assertEqual(st(d, "pie"), "pass")

    def test_pie_via_interp(self):
        self.assertEqual(st(build_elf(interp=True), "pie"), "pass")

    def test_dso(self):
        self.assertEqual(st(build_elf(interp=False), "pie"), "info")

    def test_no_pie_exec(self):
        self.assertEqual(st(build_elf(etype=2), "pie"), "fail")

    def test_other_type(self):
        self.assertEqual(st(build_elf(etype=1), "pie"), "info")


class TestNx(unittest.TestCase):
    def test_nx_ok(self):
        self.assertEqual(st(build_elf(gnu_stack=6), "nx"), "pass")

    def test_exec_stack(self):
        r = run_checks(build_elf(gnu_stack=7))
        self.assertEqual(r["nx"]["status"], "fail")
        self.assertIn("executable stack", r["nx"]["detail"])

    def test_missing_gnu_stack(self):
        self.assertEqual(st(build_elf(gnu_stack=None), "nx"), "fail")


class TestRelro(unittest.TestCase):
    def test_none(self):
        self.assertEqual(st(build_elf(), "relro"), "fail")

    def test_partial(self):
        self.assertEqual(st(build_elf(relro=True), "relro"), "warn")

    def test_full_flags(self):
        d = build_elf(relro=True, dyn_extra=[(ec.DT_FLAGS, ec.DF_BIND_NOW)])
        self.assertEqual(run_checks(d)["relro"]["detail"], "full RELRO")

    def test_full_bind_now_tag(self):
        d = build_elf(relro=True, dyn_extra=[(ec.DT_BIND_NOW, 0)])
        self.assertEqual(st(d, "relro"), "pass")

    def test_full_flags1_now(self):
        d = build_elf(relro=True, dyn_extra=[(ec.DT_FLAGS_1, ec.DF_1_NOW)])
        self.assertEqual(st(d, "relro"), "pass")

    def test_bind_now_without_relro_is_none(self):
        d = build_elf(relro=False, dyn_extra=[(ec.DT_BIND_NOW, 0)])
        self.assertEqual(st(d, "relro"), "fail")


class TestSymbols(unittest.TestCase):
    def test_canary_present(self):
        self.assertEqual(st(build_elf(syms=[b"__stack_chk_fail", b"puts"]), "canary"), "pass")

    def test_canary_absent(self):
        self.assertEqual(st(build_elf(syms=[b"puts"]), "canary"), "fail")

    def test_fortify_present(self):
        r = run_checks(build_elf(syms=[b"__memcpy_chk", b"__printf_chk", b"__stack_chk_fail"]))
        self.assertEqual(r["fortify"]["status"], "pass")
        self.assertIn("2 fortified", r["fortify"]["detail"])

    def test_fortify_absent_stack_chk_not_counted(self):
        self.assertEqual(st(build_elf(syms=[b"__stack_chk_fail"]), "fortify"), "fail")

    def test_32bit_big_endian_symbols(self):
        d = build_elf(bits=32, endian=">", syms=[b"__stack_chk_fail", b"__strcpy_chk"])
        r = run_checks(d)
        self.assertEqual(r["canary"]["status"], "pass")
        self.assertEqual(r["fortify"]["status"], "pass")

    def test_symbols_via_hash_count(self):
        d = build_elf(syms=[b"__stack_chk_fail"], hash_table=True)
        self.assertEqual(st(d, "canary"), "pass")

    def test_symbols_via_sections(self):
        d = build_elf(syms=[b"__stack_chk_fail"], sections=True)
        self.assertEqual(st(d, "canary"), "pass")

    def test_no_dynamic_no_symbols_is_na(self):
        d = build_elf(dynamic=False, interp=False, etype=2)
        r = run_checks(d)
        self.assertEqual(r["canary"]["status"], "na")
        self.assertEqual(r["fortify"]["status"], "na")

    def test_static_canary_from_symtab(self):
        d = build_elf(dynamic=False, interp=False, etype=2, sections=True,
                      symtab_names=[b"main", b"__stack_chk_fail"])
        # no dynamic section but sections give a .symtab
        self.assertEqual(st(d, "canary"), "pass")


class TestRpath(unittest.TestCase):
    def test_none(self):
        r = run_checks(build_elf())
        self.assertEqual(r["rpath"]["status"], "pass")
        self.assertEqual(r["runpath"]["status"], "pass")

    def test_benign_absolute(self):
        self.assertEqual(st(build_elf(rpath=b"/usr/lib/app"), "rpath"), "info")

    def test_relative_rpath(self):
        r = run_checks(build_elf(rpath=b"lib/private"))
        self.assertEqual(r["rpath"]["status"], "fail")
        self.assertIn("relative", r["rpath"]["detail"])

    def test_dot_runpath(self):
        self.assertEqual(st(build_elf(runpath=b"."), "runpath"), "fail")

    def test_empty_runpath_entry(self):
        self.assertEqual(st(build_elf(runpath=b"/usr/lib:"), "runpath"), "fail")

    def test_writable_tmp(self):
        r = run_checks(build_elf(runpath=b"/tmp/libs"))
        self.assertEqual(r["runpath"]["status"], "fail")
        self.assertIn("writable-looking", r["runpath"]["detail"])

    def test_origin_ok(self):
        self.assertEqual(st(build_elf(runpath=b"$ORIGIN/../lib"), "runpath"), "fail")  # climbs
        self.assertEqual(st(build_elf(runpath=b"$ORIGIN/lib"), "runpath"), "info")

    def test_control_chars_escaped(self):
        r = run_checks(build_elf(rpath=b"rel\x1b[31m"))
        self.assertNotIn("\x1b", r["rpath"]["detail"])
        self.assertIn("\\x1b", r["rpath"]["detail"])


class TestMisc(unittest.TestCase):
    def test_textrel_tag(self):
        self.assertEqual(st(build_elf(dyn_extra=[(ec.DT_TEXTREL, 0)]), "textrel"), "fail")

    def test_textrel_flag(self):
        self.assertEqual(st(build_elf(dyn_extra=[(ec.DT_FLAGS, ec.DF_TEXTREL)]), "textrel"), "fail")

    def test_no_textrel(self):
        self.assertEqual(st(build_elf(), "textrel"), "pass")

    def test_rwx_segment(self):
        self.assertEqual(st(build_elf(load_flags=0b111), "rwx"), "fail")

    def test_stripped_detection(self):
        self.assertIn("stripped", run_checks(build_elf())["stripped"]["detail"])
        d = build_elf(sections=True, symtab_names=[b"main"])
        self.assertIn("not stripped", run_checks(d)["stripped"]["detail"])

    def test_all_checks_present(self):
        self.assertEqual(sorted(run_checks(build_elf())), sorted(ec.CHECKS))

    def test_bits_and_endian_reported(self):
        for bits in (32, 64):
            for end, name in (("<", "little"), (">", "big")):
                info = ec.analyze_bytes(build_elf(bits=bits, endian=end))
                self.assertEqual(info["bits"], bits)
                self.assertEqual(info["endian"], name)

    def test_big_endian_pie_flags(self):
        d = build_elf(bits=64, endian=">", interp=False, dyn_extra=[(ec.DT_FLAGS_1, ec.DF_1_PIE)])
        self.assertEqual(st(d, "pie"), "pass")


class TestMalformed(unittest.TestCase):
    def test_not_elf(self):
        with self.assertRaises(ec.NotElf):
            ec.analyze_bytes(b"MZ" + b"\0" * 100)

    def test_empty(self):
        with self.assertRaises(ec.NotElf):
            ec.analyze_bytes(b"")

    def test_magic_only(self):
        with self.assertRaises((ec.ElfError, ec.NotElf)):
            ec.analyze_bytes(b"\x7fELF")

    def test_truncated_header(self):
        d = build_elf()[:30]
        with self.assertRaises(ec.ElfError):
            ec.analyze_bytes(d)

    def test_truncated_phdrs(self):
        d = build_elf()[:80]
        with self.assertRaises(ec.ElfError):
            ec.analyze_bytes(d)

    def test_bad_class(self):
        d = bytearray(build_elf())
        d[4] = 9
        with self.assertRaises(ec.ElfError):
            ec.analyze_bytes(bytes(d))

    def test_bad_encoding(self):
        d = bytearray(build_elf())
        d[5] = 0
        with self.assertRaises(ec.ElfError):
            ec.analyze_bytes(bytes(d))

    def test_huge_phnum(self):
        d = bytearray(build_elf())
        struct.pack_into("<H", d, 56, 0xFFFF)
        with self.assertRaises(ec.ElfError):
            ec.analyze_bytes(bytes(d))

    def test_small_phentsize(self):
        d = bytearray(build_elf())
        struct.pack_into("<H", d, 54, 8)
        with self.assertRaises(ec.ElfError):
            ec.analyze_bytes(bytes(d))

    def test_dynamic_segment_past_eof_does_not_crash(self):
        d = bytearray(build_elf())
        # corrupt PT_DYNAMIC's offset/filesz (third phdr in this layout)
        base = 64 + 56 * 2
        struct.pack_into("<QQ", d, base + 8, 10 ** 9, 0)
        struct.pack_into("<Q", d, base + 32, 10 ** 9)
        info = ec.analyze_bytes(bytes(d))
        self.assertIn("checks", info)

    def test_garbage_strtab_offset(self):
        d = build_elf(rpath=b"/x")
        # rpath string index points beyond strtab: patch DT_RPATH value
        data = bytearray(d)
        idx = data.find(struct.pack("<qQ", 15, 0)[:8])
        self.assertGreaterEqual(idx, 0)
        struct.pack_into("<Q", data, idx + 8, 10 ** 9)
        r = ec.analyze_bytes(bytes(data))["checks"]
        self.assertEqual(r["rpath"]["status"], "warn")

    def test_bogus_section_table_ignored(self):
        d = bytearray(build_elf())
        struct.pack_into("<Q", d, 40, 10 ** 9)  # e_shoff
        struct.pack_into("<H", d, 60, 5)  # e_shnum
        self.assertIn("checks", ec.analyze_bytes(bytes(d)))

    def test_random_bytes_after_magic_never_crash_badly(self):
        import random
        rnd = random.Random(1234)
        base = build_elf()
        for _ in range(300):
            d = bytearray(base)
            for _ in range(8):
                d[rnd.randrange(len(d))] = rnd.randrange(256)
            try:
                ec.analyze_bytes(bytes(d))
            except (ec.ElfError, ec.NotElf):
                pass

    def test_dynamic_loop_capped(self):
        # no DT_NULL: tags repeat until the segment ends; must terminate
        d = build_elf(dyn_extra=[(1, 1)] * 50)
        self.assertIn("checks", ec.analyze_bytes(d))


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def w(self, name, data, mode=0o644):
        p = os.path.join(self.root, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        os.chmod(p, mode)
        return p

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = ec.main(list(argv))
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def good(self):
        return build_elf(relro=True, interp=True, gnu_stack=6,
                         dyn_extra=[(ec.DT_FLAGS, ec.DF_BIND_NOW)],
                         syms=[b"__stack_chk_fail", b"__memcpy_chk"])

    def test_clean_exit_0(self):
        p = self.w("good", self.good())
        code, out, _ = self.run_main(p)
        self.assertEqual(code, 0)
        self.assertIn("full", out)

    def test_findings_exit_1(self):
        p = self.w("bad", build_elf(etype=2, gnu_stack=7))
        code, out, _ = self.run_main(p)
        self.assertEqual(code, 1)

    def test_missing_file_exit_2(self):
        code, _, err = self.run_main(os.path.join(self.root, "nope"))
        self.assertEqual(code, 2)
        self.assertIn("cannot access", err)

    def test_non_elf_single_exit_2(self):
        p = self.w("text.txt", b"hello world")
        code, _, err = self.run_main(p)
        self.assertEqual(code, 2)
        self.assertIn("not an ELF", err)

    def test_malformed_single_exit_2(self):
        p = self.w("trunc", build_elf()[:70])
        code, _, err = self.run_main(p)
        self.assertEqual(code, 2)
        self.assertIn("malformed", err)

    def test_no_args_usage_exit_2(self):
        code, _, _ = self.run_main()
        self.assertEqual(code, 2)

    def test_json_output(self):
        p = self.w("bad", build_elf(etype=2))
        code, out, _ = self.run_main("--json", p)
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertTrue(data["findings"])
        self.assertIn("pie", data["results"][0]["failing"])

    def test_directory_mode_skips_non_elf(self):
        self.w("a/good", self.good())
        self.w("a/readme.txt", b"just text")
        self.w("a/b/bad", build_elf(etype=2))
        code, out, err = self.run_main(self.root)
        self.assertEqual(code, 1)
        self.assertIn("good", out)
        self.assertNotIn("readme", out)

    def test_only_failing(self):
        self.w("good", self.good())
        self.w("bad", build_elf(etype=2))
        code, out, _ = self.run_main("--only-failing", self.root)
        self.assertIn("bad", out)
        self.assertNotIn("good", out)

    def test_only_failing_json(self):
        self.w("good", self.good())
        self.w("bad", build_elf(etype=2))
        _, out, _ = self.run_main("--json", "--only-failing", self.root)
        names = [os.path.basename(r["path"]) for r in json.loads(out)["results"]]
        self.assertEqual(names, ["bad"])

    def test_directory_all_clean_exit_0(self):
        self.w("good", self.good())
        self.w("notes.txt", b"x")
        code, _, _ = self.run_main(self.root)
        self.assertEqual(code, 0)

    def test_malformed_in_directory_is_reported(self):
        self.w("trunc", build_elf()[:70])
        code, out, _ = self.run_main(self.root)
        self.assertEqual(code, 1)
        self.assertIn("ERROR", out)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
    def test_symlinks_not_followed_in_walk(self):
        self.w("real/bad", build_elf(etype=2))
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        with open(os.path.join(outside.name, "evil"), "wb") as f:
            f.write(build_elf(etype=2))
        os.symlink(outside.name, os.path.join(self.root, "dirlink"))
        os.symlink(os.path.join(outside.name, "evil"), os.path.join(self.root, "filelink"))
        _, out, _ = self.run_main("--json", self.root)
        paths = [r["path"] for r in json.loads(out)["results"]]
        self.assertEqual(len(paths), 1)
        self.assertTrue(paths[0].endswith("bad"))

    @unittest.skipUnless(hasattr(os, "symlink") and hasattr(os, "O_NOFOLLOW"), "no nofollow")
    def test_explicit_symlink_refused(self):
        p = self.w("bad", build_elf(etype=2))
        link = os.path.join(self.root, "lnk")
        os.symlink(p, link)
        code, _, err = self.run_main(link)
        self.assertEqual(code, 2)

    def test_size_cap_skips(self):
        p = self.w("big", build_elf())
        code, out, _ = self.run_main("--max-size", "100", self.root)
        self.assertEqual(code, 0)
        self.assertIn("skipped", out)

    def test_size_cap_too_small_arg(self):
        code, _, _ = self.run_main("--max-size", "1", self.root)
        self.assertEqual(code, 2)

    @unittest.skipIf(os.name == "nt", "posix modes")
    def test_setuid_reported(self):
        p = self.w("suid", self.good(), mode=0o4755)
        _, out, _ = self.run_main("--json", p)
        r = json.loads(out)["results"][0]
        self.assertEqual(r["checks"]["setuid"]["status"], "info")
        self.assertIn("setuid", r["checks"]["setuid"]["detail"])

    @unittest.skipIf(os.name == "nt", "posix filenames")
    def test_control_chars_in_filename_escaped(self):
        p = self.w("ev\x1b[2Jil", build_elf(etype=2))
        _, out, _ = self.run_main(p)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b", out)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no fifo")
    def test_fifo_does_not_block(self):
        fifo = os.path.join(self.root, "pipe")
        os.mkfifo(fifo)
        code, _, _ = self.run_main(self.root)
        self.assertEqual(code, 0)  # fifo skipped in walk

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no fifo")
    def test_fifo_explicit_is_error(self):
        fifo = os.path.join(self.root, "pipe")
        os.mkfifo(fifo)
        code, _, _ = self.run_main(fifo)
        self.assertEqual(code, 2)

    def test_empty_file_in_directory(self):
        self.w("empty", b"")
        code, out, _ = self.run_main(self.root)
        self.assertEqual(code, 0)

    def test_inspected_file_never_executed(self):
        # an executable file whose content would create a marker if run
        marker = os.path.join(self.root, "marker")
        p = self.w("script", b"#!/bin/sh\ntouch " + marker.encode() + b"\n", mode=0o755)
        self.run_main(self.root)
        self.assertFalse(os.path.exists(marker))

    def test_clean_helper(self):
        self.assertEqual(ec.clean("a\nb\x00c‮"), "a\\x0ab\\x00c\\u202e")

    def test_path_issues_helper(self):
        self.assertEqual(ec.path_issues(["/usr/lib", "$ORIGIN"]), [])
        self.assertEqual(len(ec.path_issues(["lib", "/tmp/x", ""])), 3)


if __name__ == "__main__":
    unittest.main()
