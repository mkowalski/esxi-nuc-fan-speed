import hashlib
import importlib.util
from pathlib import Path
import unittest
import subprocess
import sys
import tempfile
import json

ROOT=Path(__file__).resolve().parents[1]

class StartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('fan_start',ROOT/'scripts/esxi-fan-start.py')
        cls.start=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.start)

    def test_runtime_boot_control_and_exact_artifact_preflight(self):
        false='preventFreePageMapping Bool FALSE FALSE FALSE description\n'
        kernel='execInstalledOnly Bool FALSE FALSE FALSE description\n'
        self.start.validate_preflight('VMware ESXi 8.0.3 build-25429389',self.start.KERNEL_SHA,self.start.ARTIFACT_SHA,false,kernel,1,set())
        cases=[('version','other'),('kernel_sha','0'*64),('artifact_sha','0'*64),('prevent',false.replace('FALSE FALSE','FALSE TRUE')),('execution',kernel.replace('FALSE FALSE','FALSE TRUE')),('policy',0),('modules',{'nuc_fan_monitor'})]
        for key,value in cases:
            args={'version':'VMware ESXi 8.0.3 build-25429389','kernel_sha':self.start.KERNEL_SHA,'artifact_sha':self.start.ARTIFACT_SHA,'prevent':false,'execution':kernel,'policy':1,'modules':set()}
            args[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.start.validate_preflight(**args)

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
