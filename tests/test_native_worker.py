from pathlib import Path
import subprocess
import json
import tempfile
import unittest
import struct
import runpy
import re

ROOT=Path(__file__).resolve().parent

class ResidentTests(unittest.TestCase):
    def test_stop_publication_handshake_cannot_use_store_buffered_release_stores(self):
        flags=runpy.run_path(str(ROOT/'test_native_core.py'))['FLAGS']
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            ir=Path(directory)/'monitor.ll'
            r=subprocess.run(['/usr/bin/clang',*flags,'-fno-inline','-S','-emit-llvm',str(ROOT.parent/'src/monitor.c'),'-o',str(ir)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            body=re.search(r'define[^\n]*@store_flag\([^\n]*\)[^\n]*\{(.*?)^}',ir.read_text(),re.S|re.M)
            self.assertIsNotNone(body)
            self.assertIn('seq_cst',body[1]);self.assertNotIn(' release ',body[1])

    def test_native_elf_has_only_expected_resident_imports_and_entrypoints(self):
        flags=runpy.run_path(str(ROOT/'test_native_core.py'))['FLAGS']
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            obj=Path(directory)/'monitor.o'
            r=subprocess.run(['/usr/bin/clang',*flags,'-c',str(ROOT.parent/'src/monitor.c'),'-o',str(obj)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            b=obj.read_bytes();at=struct.unpack_from('<Q',b,40)[0];width,count,ni=struct.unpack_from('<HHH',b,58)
            sections=[struct.unpack_from('<IIQQQQIIQQ',b,at+i*width) for i in range(count)]
            imports=set();exports=set();relocations=set()
            for s in sections:
                self.assertFalse(s[2]&0x10000000)
                if s[1]==4:
                    for pos in range(s[4],s[4]+s[5],s[9]):relocations.add(struct.unpack_from('<QQq',b,pos)[1]&0xffffffff)
                if s[1]!=2:continue
                st=sections[s[6]];strings=b[st[4]:st[4]+st[5]]
                for pos in range(s[4],s[4]+s[5],s[9]):
                    n,info,other,index,value,size=struct.unpack_from('<IBBHQQ',b,pos);name=strings[n:strings.index(0,n)].decode()
                    if name and not index:imports.add(name)
                    if index and info>>4 in (1,2):exports.add(name)
            self.assertEqual(exports,{'init_module','cleanup_module'})
            self.assertTrue(relocations<={1,2},relocations)
            self.assertEqual(imports,{'_vmk_LogMessage','vmk_ModuleCurrentID','vmk_ACPIDeviceIterate','vmk_ACPIQueryInfo','vmk_ACPIQueryIOResources','vmk_ModuleIncUseCount','vmk_ModuleDecUseCount','vmk_ModuleGetHeapID','vmk_ModuleSetHeapID','vmk_NameInitialize','vmk_HeapCreate','vmk_HeapDestroySync','vmk_ACPIMapIOResource','vmk_ACPIUnmapIOResource','vmk_MappedResourceRead8','vmk_WorldCreate','vmk_WorldSleep','vmk_WorldDestroy','vmk_WorldWaitForDeath','vmk_WorldCreateAllocSize'})
            dis=subprocess.run(['/usr/bin/objdump','-dr',str(obj)],capture_output=True,text=True,check=True).stdout
            self.assertNotRegex(dis,r'%(?:xmm|ymm|zmm|mm)[0-9]')
            self.assertNotRegex(dis,r'\s(?:inb|inw|inl|outb|outw|outl)\s')

    def test_actual_worker_repeated_reads_and_failure_lifetimes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            binary=Path(directory)/'fixture'
            r=subprocess.run(['/usr/bin/clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread',str(ROOT/'native/worker.c'),'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            def run(case):
                r=subprocess.run([str(binary),case],capture_output=True,text=True,timeout=10)
                self.assertEqual(r.returncode,0,r.stderr);return json.loads(r.stdout)
            for case in ['ok','join-once-error']:
                with self.subTest(case=case):
                    result=run(case);self.assertEqual(result['valid'],3);self.assertEqual(result['maps'],3);self.assertEqual(result['unmaps'],3)
                    self.assertEqual(result['creates'],1);self.assertEqual(result['destroys'],1);self.assertEqual(result['heap_live'],0)
                    self.assertEqual(result['pins'],0);self.assertEqual(result['idle_pins'],0);self.assertEqual(result['cleanup_returned'],1)
                    self.assertEqual(result['joins'],2 if case=='join-once-error' else 1);self.assertGreaterEqual(result['invalid'],1)
                    self.assertIn('valid=1 rpm=3125',result['log'])
                    self.assertEqual(result['stop_watermark'],3)
            result=run('create-error');self.assertEqual(result['maps'],0);self.assertEqual(result['heap_live'],0);self.assertEqual(result['pins'],0);self.assertGreaterEqual(result['invalid'],1)
            result=run('startup-timeout');self.assertEqual(result['maps'],0);self.assertEqual(result['pins'],1);self.assertEqual(result['heap_live'],1);self.assertEqual(result['cleanup_returned'],0)
            result=run('zero-id');self.assertEqual(result['maps'],0);self.assertEqual(result['pins'],1);self.assertEqual(result['heap_live'],1);self.assertEqual(result['destroys'],0)
            result=run('null-heap');self.assertEqual(result['maps'],0);self.assertEqual(result['pins'],0);self.assertEqual(result['heap_live'],0);self.assertEqual(result['destroys'],0)
            result=run('unmap-error');self.assertEqual(result['maps'],1);self.assertEqual(result['pins'],1);self.assertEqual(result['heap_live'],1);self.assertEqual(result['valid'],0);self.assertEqual(result['destroys'],0)
            result=run('pin-rejected');self.assertEqual(result['maps'],0);self.assertEqual(result['pins'],0);self.assertEqual(result['heap_live'],0);self.assertEqual(result['cleanup_returned'],1)
            result=run('destroy-error');self.assertEqual(result['parks'],1);self.assertEqual(result['cleanup_returned'],0);self.assertEqual(result['heap_live'],1)
            result=run('publish-race');self.assertEqual(result['valid'],1);self.assertEqual(result['stop_watermark'],1);self.assertEqual(result['stop_before_publish'],0);self.assertEqual(result['cleanup_returned'],1)

if __name__=='__main__':unittest.main(verbosity=2)
