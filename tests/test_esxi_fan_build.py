import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]

class FanBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('fan_build',ROOT/'scripts/build-esxi-fan-monitor.py')
        cls.builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.builder)

    def test_build_rejects_an_unverified_core_header_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);header=root/'fan_core.h';output=root/'monitor.o'
            header.write_text('/* unverified replacement */\n')
            with patch.object(self.builder,'CORE',header,create=True):
                with self.assertRaises(ValueError):self.builder.build(output,'/usr/bin/clang')
            self.assertFalse(output.exists())

    def test_reproducible_real_elf_and_rejection_of_narrow_pointer_relocations(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'monitor.o'
            manifest=self.builder.build(output,'/usr/bin/clang')
            data=output.read_bytes()
            self.assertEqual(manifest['artifact_sha256'],hashlib.sha256(data).hexdigest())
            self.assertEqual(manifest['artifact_sha256'],'6efcb75285b71135fadd0c26fa50fdeb2d81a097ebb3dd201d0b6e7180517fde')
            self.assertEqual(manifest['source_sha256'],'18dab6a537bf35405f10baa4bd4c68b3a7c11a62c8ee8781221fcca3836ccc8b')
            self.assertEqual(manifest['core_sha256'],'8f3f4711964e5a9bb20441348a9b48e48b4d552d900d320958492321f2ecac49')
            self.assertEqual(manifest['relocation_types'],[1])
            self.assertEqual(manifest['exports'],['cleanup_module','init_module'])
            bad=bytearray(data);off=struct.unpack_from('<Q',bad,40)[0];width,count,_=struct.unpack_from('<HHH',bad,58)
            sections=[struct.unpack_from('<IIQQQQIIQQ',bad,off+i*width) for i in range(count)]
            section=next(s for s in sections if s[1]==4 and s[5])
            info=struct.unpack_from('<Q',bad,section[4]+8)[0]
            struct.pack_into('<Q',bad,section[4]+8,(info&~0xffffffff)|11)
            with self.assertRaises(ValueError):self.builder.inspect_elf(bytes(bad))
            with self.assertRaises(FileExistsError):self.builder.build(output,'/usr/bin/clang')
            self.assertEqual(output.read_bytes(),data)

if __name__=='__main__':unittest.main(verbosity=2)
