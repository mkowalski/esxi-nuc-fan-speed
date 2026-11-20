import hashlib
import importlib.util
from pathlib import Path
import unittest
import subprocess
import sys
import tempfile
import json

ROOT=Path(__file__).resolve().parents[1]
QUALIFIED_KERNEL_SHA='3c55688c314300ae90849b34959ad3dd5d66d2d5b14d3349a1204e470df9ac52'
QUALIFIED_ARTIFACT_SHA='6efcb75285b71135fadd0c26fa50fdeb2d81a097ebb3dd201d0b6e7180517fde'


def qualified_args(version):
    return {'version':version,'kernel_sha':QUALIFIED_KERNEL_SHA,
            'artifact_sha':QUALIFIED_ARTIFACT_SHA,
            'prevent':'preventFreePageMapping Bool FALSE FALSE FALSE description\n',
            'execution':'execInstalledOnly Bool FALSE FALSE FALSE description\n',
            'policy':1,'modules':set()}

class StartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('fan_start',ROOT/'scripts/esxi-fan-start.py')
        cls.start=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.start)

    def test_runtime_boot_control_and_exact_artifact_preflight(self):
        false='preventFreePageMapping Bool FALSE FALSE FALSE description\n'
        kernel='execInstalledOnly Bool FALSE FALSE FALSE description\n'
        self.start.validate_preflight(**qualified_args('VMware ESXi 8.0.3 build-25429389'))
        cases=[('version','other'),('kernel_sha','0'*64),('artifact_sha','0'*64),('prevent',false.replace('FALSE FALSE','FALSE TRUE')),('execution',kernel.replace('FALSE FALSE','FALSE TRUE')),('policy',0),('modules',{'nuc_fan_monitor'})]
        for version in ('VMware ESXi 8.0.3 build-25429389','VMware ESXi 8.0.3 build-25595708'):
            for key,value in cases:
                args=qualified_args(version)
                args[key]=value
                with self.subTest(version=version,key=key),self.assertRaises(ValueError):self.start.validate_preflight(**args)

    def test_u3j_and_u3k_accept_the_measured_kernel_and_object(self):
        # Rejecting U3k despite identical qualified binaries prevents RPM startup.
        for build in ('25429389','25595708'):
            version=f'VMware ESXi 8.0.3 build-{build}\nVMware ESXi 8.0 Update 3\n'
            with self.subTest(build=build):
                try:
                    self.start.validate_preflight(**qualified_args(version))
                except ValueError as error:
                    self.fail(f'Qualified build {build} rejected: {error}')

    def test_version_line_must_match_a_qualified_release_exactly(self):
        # Substring matching can accidentally admit an unqualified release line.
        versions=('', 'VMware ESXi 8.0.3 build-254293890',
                  'VMware ESXi 8.0.3 build-255957080',
                  'prefix VMware ESXi 8.0.3 build-25429389',
                  'VMware ESXi 8.0.3 build-25926933',
                  'VMware ESXi 9.0.0 build-25595708')
        for version in versions:
            with self.subTest(version=version),self.assertRaises(ValueError):
                self.start.validate_preflight(**qualified_args(version))

    def test_loaded_module_is_not_operational_without_a_new_valid_sample(self):
        clock=[0.0];reads=[0]
        def texts():
            reads[0]+=1
            return ['nuc_fan_monitor: sample new'] if reads[0]>=3 else ['no observation']
        def pause(seconds):clock[0]+=seconds
        parser=lambda text,now:{'fan_rpm':3125,'acquired_ns':now}
        result=self.start.wait_for_sample(texts,parser,lambda:100,lambda:clock[0],pause)
        self.assertEqual(result,{'fan_rpm':3125,'acquired_ns':100})
        def invalid(text,now):raise ValueError('invalid latest')
        with self.assertRaises(ValueError):self.start.wait_for_sample(lambda:['nuc_fan_monitor: sample failed'],invalid,lambda:100,lambda:0,pause)

    def test_policy_owner_is_the_exact_runtime_proven_serialized_program(self):
        self.assertEqual(hashlib.sha256(self.start.POLICY_GUARD.encode()).hexdigest(),'00ad86b10779b694dba68966bcda0aa2d64e9324ab42fe84723e9fbcd8ff0b70')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'state';trace=root/'trace';fake=root/'cli.py'
            fake.write_text('import sys,time\nfrom pathlib import Path\ns,t,value=sys.argv[1:]\nwith Path(t).open("a") as f:f.write("start"+value+"\\n")\nif value=="0":time.sleep(0.1)\nPath(s).write_text(value)\nwith Path(t).open("a") as f:f.write("done"+value+"\\n")\n')
            for mode in ['eof-during-disable','restore','eof-before-go']:
                with self.subTest(mode=mode):
                    state.write_text('1');trace.write_text('')
                    args=[sys.executable,str(fake),str(state),str(trace)]
                    child=subprocess.Popen([sys.executable,'-I','-c',self.start.POLICY_GUARD,json.dumps(args)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    self.assertEqual(child.stdout.readline(),b'armed\n')
                    if mode!='eof-before-go':
                        child.stdin.write(b'go\n');child.stdin.flush();self.assertEqual(child.stdout.readline(),b'disabling\n')
                        if mode=='restore':
                            self.assertEqual(child.stdout.readline(),b'disabled\n');child.stdin.write(b'restore\n');child.stdin.flush()
                    child.stdin.close();self.assertEqual(child.wait(timeout=5),0)
                    self.assertEqual(child.stderr.read(),b'');child.stderr.close();child.stdout.close()
                    self.assertEqual(state.read_text(),'1')
                    self.assertEqual(trace.read_text().splitlines(),['start0','done0','start1','done1'] if mode!='eof-before-go' else ['start1','done1'])

if __name__=='__main__':unittest.main(verbosity=2)
