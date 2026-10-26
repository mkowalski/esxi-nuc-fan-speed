import importlib.util
from pathlib import Path
import unittest
import tempfile
import io
import json
from unittest.mock import patch


ROOT=Path(__file__).resolve().parents[1]
STAMP=1793019518123456789
PREFIX='2026-10-26T12:58:38.123456789Z In(182) vmkernel: cpu2:123)'
GOOD='nuc_fan_monitor: sample v=1 seq=20 status=0x0 valid=1 rpm=3125 reads=10 attempt=1 signature_ok=1 type=1 high=12 low=53 high_after=12'


class FanReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path=ROOT/'scripts/esxi-fan-reader.py'
        spec=importlib.util.spec_from_file_location('esxi_fan_reader',path)
        cls.reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.reader)

    def test_validated_native_bytes_and_original_nanoseconds_are_returned(self):
        result=self.reader.latest_sample([PREFIX+GOOD],STAMP+1_000_000_000)
        self.assertEqual(result,{'version':1,'acquired_ns':STAMP,'sequence':20,'fan_rpm':3125})
        self.assertEqual(self.reader.latest_sample([PREFIX+GOOD,PREFIX+GOOD],STAMP),result)
        normal=PREFIX.replace('cpu2:123)','')+GOOD
        self.assertEqual(self.reader.latest_sample([normal],STAMP),result)

    def test_sample_payload_in_an_unrelated_log_origin_is_rejected(self):
        forged='2026-10-26T12:58:38.123456789Z Wa(180) other: '+GOOD
        with self.assertRaises(ValueError):self.reader.latest_sample([forged],STAMP)
        with self.assertRaises(ValueError):self.reader.latest_sample([PREFIX.replace('In(182) vmkernel:','Wa(180) vmkwarning: WARNING:')+GOOD],STAMP)

    def test_incomplete_latest_sample_and_nested_diagnostic_echo_are_rejected(self):
        latest=PREFIX.replace('38.123456789','39.123456789')+'nuc_fan_monitor: sample\n'
        with self.assertRaises(ValueError):self.reader.latest_sample([PREFIX+GOOD+'\n'+latest],STAMP+2_000_000_000)
        echoed=PREFIX+'nuc_fan_monitor: diagnostic echo: '+GOOD
        with self.assertRaises(ValueError):self.reader.latest_sample([echoed],STAMP)

    def test_latest_error_or_corruption_never_falls_back_to_old_success(self):
        newer=PREFIX.replace('38.123456789','39.123456789')
        for bad in [GOOD.replace('status=0x0','status=0xbad0001').replace('valid=1','valid=0'),
                    GOOD.replace('rpm=3125','rpm=3126'),GOOD.replace('v=1','v=2'),GOOD+' pinned=0',
                    GOOD+' valid=1',GOOD.replace('high=12','high=0xG')]:
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                self.reader.latest_sample([PREFIX+GOOD+'\n'+newer+bad],STAMP+2_000_000_000)
        with self.assertRaises(ValueError):
            self.reader.latest_sample([PREFIX+GOOD,'not-a-time '+GOOD],STAMP)

    def test_stale_future_missing_and_conflicting_observations_are_rejected(self):
        for logs,now in [([PREFIX+GOOD],STAMP+90_000_000_001),([PREFIX+GOOD],STAMP-2_000_000_001),
                         (['unrelated log'],STAMP),([PREFIX+GOOD,PREFIX+GOOD.replace('seq=20','seq=21')],STAMP)]:
            with self.subTest(logs=logs,now=now),self.assertRaises(ValueError):self.reader.latest_sample(logs,now)

    def test_raw_signature_type_stability_budget_and_sentinel_gates(self):
        for token,value in [('signature_ok=1','signature_ok=0'),('type=1','type=2'),('high_after=12','high_after=13'),
                            ('reads=10','reads=17'),('attempt=1','attempt=4'),('reads=10','reads=11'),('seq=20','seq=0')]:
            with self.subTest(value=value),self.assertRaises(ValueError):
                self.reader.latest_sample([PREFIX+GOOD.replace(token,value)],STAMP)
        sentinel=GOOD.replace('rpm=3125','rpm=65535').replace('high=12','high=255').replace('low=53','low=255').replace('high_after=12','high_after=255')
        with self.assertRaises(ValueError):self.reader.latest_sample([PREFIX+sentinel],STAMP)
        zero=GOOD.replace('rpm=3125','rpm=0').replace('high=12','high=0').replace('low=53','low=0').replace('high_after=12','high_after=0')
        self.assertEqual(self.reader.latest_sample([PREFIX+zero],STAMP)['fan_rpm'],0)

    def test_exact_forced_command_and_no_arguments(self):
        self.reader.require_forced_command('read-fan',[])
        for command,args in [(None,[]),('',[]),('sh',[]),('read-fan; id',[]),('read-fan x',[]),('read-fan',['x'])]:
            with self.subTest(command=command,args=args),self.assertRaises(ValueError):
                self.reader.require_forced_command(command,args)

    def test_tail_read_is_bounded_and_main_rejects_commands_before_log_io(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'kernel.log'
            path.write_text('unrelated\n'*50000+PREFIX+GOOD+'\n')
            with patch.object(self.reader,'LOGS',(str(path),str(Path(directory)/'missing'))):
                texts=self.reader.read_log_texts()
            self.assertEqual(len(texts),1)
            self.assertLessEqual(len(texts[0].encode()),256*1024)
            self.assertEqual(self.reader.latest_sample(texts,STAMP)['fan_rpm'],3125)
        output=io.StringIO()
        with patch.dict(self.reader.os.environ,{'SSH_ORIGINAL_COMMAND':'read-fan; id'}),patch.object(self.reader.sys,'argv',['reader']),patch.object(self.reader,'read_log_texts',side_effect=AssertionError('must not read')),patch('sys.stdout',output):
            self.assertEqual(self.reader.main(),1)
        self.assertFalse(json.loads(output.getvalue())['success'])


if __name__=='__main__':unittest.main(verbosity=2)
