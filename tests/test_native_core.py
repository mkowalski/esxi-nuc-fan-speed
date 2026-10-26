"""Mutations caught: wrong address/type, excess reads, false RPM, premature free/unpin."""
import json
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent
FLAGS=['--target=x86_64-unknown-linux-gnu','-ffreestanding','-O2','-fno-stack-protector',
       '-fno-pic','-fno-pie','-mcmodel=large','-mno-red-zone','-mno-sse','-mno-sse2','-mno-mmx',
       '-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-addrsig','-std=c11','-Wall','-Wextra','-Werror']

class ProbeTests(unittest.TestCase):
    def test_x86_artifact_limits_imports_and_emits_reserved_metadata(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            obj=Path(directory)/'proof.o'
            r=subprocess.run(['/usr/bin/clang',*FLAGS,'-x','c','-c',str(ROOT.parent/'src/fan_core.h'),'-o',str(obj)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            b=obj.read_bytes();self.assertEqual(b[:6],b'\x7fELF\x02\x01')
            self.assertEqual(struct.unpack_from('<HH',b,16),(1,62))
            at=struct.unpack_from('<Q',b,40)[0];width,count,ni=struct.unpack_from('<HHH',b,58)
            sections=[struct.unpack_from('<IIQQQQIIQQ',b,at+i*width) for i in range(count)]
            s=sections[ni];names=b[s[4]:s[4]+s[5]]
            named={names[s[0]:names.index(0,s[0])].decode():s for s in sections}
            imports=set();exports=set();metadata={};relocs=set()
            for s in sections:
                self.assertFalse(s[2]&0x10000000)
                if s[1]==2:
                    st=sections[s[6]];strings=b[st[4]:st[4]+st[5]]
                    for pos in range(s[4],s[4]+s[5],s[9]):
                        n,info,other,index,value,size=struct.unpack_from('<IBBHQQ',b,pos)
                        name=strings[n:strings.index(0,n)].decode()
                        if name and not index:imports.add(name)
                        if index and info>>4 in (1,2):exports.add(name)
                        if name.startswith('__vmk_') and name.endswith('Info_str'):
                            self.assertEqual(sections[index],named['.vmkmodinfo']);owner=sections[index]
                            metadata[name]=b[owner[4]+value:owner[4]+value+size]
                if s[1]==4:
                    for pos in range(s[4],s[4]+s[5],s[9]):relocs.add(struct.unpack_from('<QQq',b,pos)[1]&0xffffffff)
            self.assertEqual(imports,{'vmk_ModuleCurrentID','_vmk_WarningMessage','vmk_ACPIDeviceIterate','vmk_ACPIQueryInfo','vmk_ACPIQueryIOResources','vmk_ModuleIncUseCount','vmk_ModuleDecUseCount','vmk_ModuleGetHeapID','vmk_ModuleSetHeapID','vmk_NameInitialize','vmk_HeapCreate','vmk_HeapDestroySync','vmk_ACPIMapIOResource','vmk_ACPIUnmapIOResource','vmk_MappedResourceRead8'})
            self.assertEqual(exports,{'init_module','cleanup_module'})
            self.assertEqual(metadata,{'__vmk_licenseInfo_str':b'license=BSD\0','__vmk_buildTypeInfo_str':b'buildType=release\0','__vmk_versionInfo_str':b'version=0.0.1-fan-proof\0','__vmk_nsRequiredInfo_str':b'nsRequired=com.vmware.vmkapi#v2_13_0_0\0'})
            self.assertTrue(relocs<={1,2},relocs)
            self.assertNotIn('.eh_frame',named);self.assertNotIn('.llvm_addrsig',named)
            dis=subprocess.run(['/usr/bin/objdump','-dr',str(obj)],capture_output=True,text=True,check=True).stdout
            self.assertNotRegex(dis,r'%(?:xmm|ymm|zmm|mm)[0-9]')
            self.assertNotRegex(dis,r'\s(?:inb|inw|inl|outb|outw|outl)\s')

    def test_real_probe_gates_sampling_and_lifetime(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            binary=Path(directory)/'fixture'
            r=subprocess.run(['/usr/bin/clang','-std=c11','-O2','-Wall','-Wextra','-Werror',str(ROOT/'native/core.c'),'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            def run(case):
                r=subprocess.run([str(binary),case],capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stderr)
                return json.loads(r.stdout)
            ok=run('ok')
            self.assertIn('valid=1 rpm=1968',ok['log']);self.assertEqual(ok['reads'],10)
            self.assertEqual(ok['trace'],'PHAM'+'R'*10+'Uhp')
            self.assertEqual(ok['offsets'],[0x210400,0x210401,0x210402,0x210403,0x210404,0x210405,0x21041c,0x21041d,0x21041e,0x21041d])
            self.assertIn('safe_to_unload=1',ok['log']);self.assertEqual(ok['pins'],0)
            for case in ['power','disabled','cache-error','unregistered','magic','busy','no-registration','null-ledger','table-overflow','private-count','raw-kind','raw-flags','range','prefix','null-name','count','iterate-error','info-error','resources-error','duplicate','cap','pin-error','old-heap','name-error','heap-error','associate-error']:
                with self.subTest(case=case):
                    r=run(case);self.assertEqual(r['maps'],0);self.assertEqual(r['reads'],0)
                    self.assertIn('valid=0',r['log']);self.assertEqual(r['pins'],0);self.assertEqual(r['heap_live'],0)
            for case in ['port-type','attrs','length','va-overflow','state-after-map']:
                with self.subTest(case=case):
                    r=run(case);self.assertEqual(r['maps'],1);self.assertEqual(r['unmaps'],1);self.assertEqual(r['reads'],0)
                    self.assertIn('valid=0',r['log']);self.assertEqual(r['pins'],0);self.assertIn('safe_to_unload=1',r['log'])
            for case in ['signature','fan-type','read-error','all-ones','unstable']:
                with self.subTest(case=case):
                    r=run(case);self.assertEqual(r['unmaps'],1);self.assertLessEqual(r['reads'],16)
                    self.assertIn('valid=0',r['log']);self.assertEqual(r['pins'],0)
            self.assertEqual(run('signature')['reads'],1)
            self.assertEqual(run('unstable')['reads'],16)
            retry=run('retry');self.assertEqual(retry['reads'],13);self.assertIn('valid=1 rpm=1968',retry['log'])
            self.assertIn('valid=1 rpm=0',run('zero')['log'])
            r=run('map-error');self.assertEqual(r['unmaps'],0);self.assertEqual(r['destroys'],1);self.assertEqual(r['pins'],0)
            for case in ['map-error-dirty','unmap-error','dirty-after-unmap','destroy-error','unpin-error']:
                with self.subTest(case=case):
                    r=run(case);self.assertIn('safe_to_unload=0',r['log']);self.assertIn('valid=0',r['log'])
                    self.assertEqual(r['pins'],1);self.assertEqual(r['loader_status'],0)
                    if case in ['map-error-dirty','unmap-error','dirty-after-unmap']:self.assertEqual(r['destroys'],0)

if __name__=='__main__':unittest.main(verbosity=2)
