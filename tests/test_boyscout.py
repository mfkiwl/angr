import nose
import angr
import unittest

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

import logging
l = logging.getLogger('angr.test_boyscout')

class TestMain(unittest.TestCase):
    def _main(self,file_path, arch, endianness):
        f = os.path.join(test_location, file_path)
        l.debug("Processing %s", f)

        p = angr.Project(f,
            load_options={
                'main_opts': {
                    'backend': 'blob',
                    'base_addr': 0x10000,
                    'entry_point': 0x10000,
                    'arch': 'ARM',
                    'offset': 0,
                }
            },
            auto_load_libs=False
        )
        bs = p.analyses.BoyScout()

        nose.tools.assert_in(arch, bs.arch)
        nose.tools.assert_equal(bs.endianness, endianness)


    def test_i386_all(self):
        self._main("i386/all", "X86", "Iend_LE")

    def test_i386_fauxware(self):
        self._main("i386/fauxware", "X86", "Iend_LE")

    def test_x86_64_all(self):
        self._main("x86_64/all", "AMD64", "Iend_LE")

    def test_x86_64_basic_buffer_overflows(self):
        self._main("x86_64/basic_buffer_overflows", "AMD64", "Iend_LE")

    def test_x86_64_cfg_0(self):
        self._main("x86_64/cfg_0", "AMD64", "Iend_LE")

    def test_x86_64_cfg_1(self):
        self._main("x86_64/cfg_1", "AMD64", "Iend_LE")

    def test_armel_fauxware(self):
        self._main("armel/fauxware", "ARM", "Iend_LE")

    def test_armel_test_division(self):
        self._main("armel/test_division", "ARM", "Iend_LE")

    def test_armhf_fauxware(self):
        self._main("armhf/fauxware", "ARM", "Iend_LE")

    def test_mips_allcmps(self):
        self._main("mips/allcmps", "MIPS32", "Iend_BE")

    def test_mips_manysum(self):
        self._main("mips/manysum", "MIPS32", "Iend_BE")

    def test_mipsel_busybox(self):
        self._main("mipsel/busybox", "MIPS32", "Iend_LE")

    def test_mipsel_fauxware(self):
        self._main("mipsel/fauxware", "MIPS32", "Iend_LE")

if __name__ == "__main__":
    unittest.main()
