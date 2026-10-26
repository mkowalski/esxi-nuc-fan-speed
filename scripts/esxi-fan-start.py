#!/bin/python3
"""Start only the reviewed NUC monitor; keep execution enforcement enabled afterward."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import runpy
import time
import re


OBJECT = Path('/vmfs/volumes/datastore1/monitoring/nuc_fan_monitor.o')
NAME = 'nuc_fan_monitor'
CLI = '/bin/esxcli'
LOADER = '/bin/vmkload_mod'
OPTION = '/User/ExecInstalledOnly'
KERNEL_SHA = '3c55688c314300ae90849b34959ad3dd5d66d2d5b14d3349a1204e470df9ac52'
ARTIFACT_SHA = '6efcb75285b71135fadd0c26fa50fdeb2d81a097ebb3dd201d0b6e7180517fde'
GUARD_SHA = '00ad86b10779b694dba68966bcda0aa2d64e9324ab42fe84723e9fbcd8ff0b70'
READER_SHA = 'de583a8c124da7e6d27f3a31b8ff27adb4c361a0bc6df407bc1d638de70f74ba'
# Exact serialized owner exercised by real-child EOF/deadline tests and live trials.
POLICY_GUARD = r'''
import json,select,subprocess,sys,time
command=json.loads(sys.argv[1])
started=time.monotonic()
print('armed',flush=True)
restore_rc=1
try:
 ready,_,_=select.select([sys.stdin],[],[],5)
 message=sys.stdin.buffer.readline() if ready else b''
 if message==b'go\n':
  print('disabling',flush=True)
  r=subprocess.run(command+['0'],capture_output=True,text=True,timeout=15)
  if r.returncode:raise RuntimeError('disable failed')
  print('disabled',flush=True)
  ready,_,_=select.select([sys.stdin],[],[],max(0,45-(time.monotonic()-started)))
  if ready:sys.stdin.buffer.readline()
except Exception as error:
 print(json.dumps({'guard_error':type(error).__name__}),flush=True)
finally:
 try:
  r=subprocess.run(command+['1'],capture_output=True,text=True,timeout=15)
  restore_rc=r.returncode
  print(json.dumps({'restore_attempted':True,'returncode':restore_rc}),flush=True)
 except Exception as error:
  print(json.dumps({'restore_error':type(error).__name__}),flush=True)
sys.exit(restore_rc)
'''


def boot_false(text: str, key: str) -> bool:
    rows = [line.split() for line in text.splitlines() if line.split() and line.split()[0] == key]
    return len(rows) == 1 and len(rows[0]) >= 5 and rows[0][1] == 'Bool' and rows[0][3] == 'FALSE'


def validate_preflight(version: str, kernel_sha: str, artifact_sha: str,
                       prevent: str, execution: str, policy: int, modules: set) -> None:
    if not ('8.0.3' in version and '25429389' in version and kernel_sha == KERNEL_SHA and
            artifact_sha == ARTIFACT_SHA and policy == 1 and NAME not in modules and
            boot_false(prevent, 'preventFreePageMapping') and boot_false(execution, 'execInstalledOnly')):
        raise ValueError('Unsupported target, policy, artifact or existing module; no change permitted')


def kernel_digest() -> str:
    digest = hashlib.sha256()
    total = 0
    with gzip.open('/bootbank/k.b00', 'rb') as source:
        while True:
            block = source.read(65536)
            if not block:
                break
            total += len(block)
            if total > 96 * 1024 * 1024:
                raise ValueError('Oversized kernel image')
            digest.update(block)
    return digest.hexdigest()


def command(args: list, timeout: int = 20) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          errors='replace', timeout=timeout).stdout


def modules() -> set:
    return {line.split()[0] for line in command([LOADER, '-l']).splitlines()[1:] if line.split()}


def policy() -> int:
    text = command([CLI, 'system', 'settings', 'advanced', 'list', '-o', OPTION])
    fields = dict(line.strip().split(':', 1) for line in text.splitlines() if ':' in line)
    return int(fields['Int Value'].strip())


def wait_for_sample(read_texts, parser, now_ns, monotonic, pause) -> dict:
    deadline = monotonic() + 5
    while monotonic() < deadline:
        texts = read_texts()
        if any(re.search(r'nuc_fan_monitor:\s*sample(?:\s|$)', text) for text in texts):
            return parser(texts, now_ns())
        pause(0.05)
    raise TimeoutError('No new operational sampler observation')


def main() -> int:
    guard = None
    loaded = False
    restored = False
    failure = None
    reader = None
    offsets = {}
    report = {'loaded': False, 'enforcement': None, 'artifact_sha256': ARTIFACT_SHA}
    try:
        if sys.argv[1:] or os.geteuid() != 0:
            raise ValueError('Fixed root-only loader; no arguments')
        if OBJECT.is_symlink() or OBJECT.stat().st_uid != 0 or OBJECT.stat().st_mode & 0o022:
            raise ValueError('Untrusted monitor file')
        if OBJECT.parent.stat().st_uid != 0 or OBJECT.parent.stat().st_mode & 0o022:
            raise ValueError('Untrusted monitor directory')
        reader_file = OBJECT.parent / 'esxi-fan-reader.py'
        if reader_file.is_symlink() or reader_file.stat().st_uid != 0 or reader_file.stat().st_mode & 0o022:
            raise ValueError('Untrusted cached reader')
        if hashlib.sha256(reader_file.read_bytes()).hexdigest() != READER_SHA:
            raise ValueError('Cached reader changed')
        reader = runpy.run_path(str(reader_file))
        validate_preflight(command(['/bin/vmware', '-vl']), kernel_digest(),
            hashlib.sha256(OBJECT.read_bytes()).hexdigest(),
            command([CLI, 'system', 'settings', 'kernel', 'list', '-o', 'preventFreePageMapping']),
            command([CLI, 'system', 'settings', 'kernel', 'list', '-o', 'execInstalledOnly']), policy(), modules())
        if hashlib.sha256(POLICY_GUARD.encode()).hexdigest() != GUARD_SHA:
            raise ValueError('Policy owner changed')
        for name in reader['LOGS']:
            path = Path(name)
            if path.is_file():
                stat = path.stat()
                offsets[name] = (stat.st_ino, stat.st_size)
        if not offsets:
            raise ValueError('No native log sinks')
        setter = [CLI, 'system', 'settings', 'advanced', 'set', '-o', OPTION, '-i']
        guard = subprocess.Popen(['/bin/python3', '-I', '-c', POLICY_GUARD, json.dumps(setter)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True, bufsize=0)
        ready, _, _ = select.select([guard.stdout], [], [], 5)
        if not ready or guard.stdout.readline() != b'armed\n':
            raise RuntimeError('Policy owner did not arm')
        guard.stdin.write(b'go\n')
        guard.stdin.flush()
        for marker in (b'disabling\n', b'disabled\n'):
            ready, _, _ = select.select([guard.stdout], [], [], 20)
            if not ready or guard.stdout.readline() != marker:
                raise RuntimeError('Policy disable was not serialized/confirmed')
        if policy() != 0:
            raise RuntimeError('Temporary loader policy not confirmed')
        completed = subprocess.run([LOADER, '-m', NAME, str(OBJECT)], capture_output=True,
            text=True, errors='replace', timeout=15)
        loaded = completed.returncode == 0
        report['load_returncode'] = completed.returncode
        if not loaded:
            raise RuntimeError('Native loader refused the monitor')
    except Exception as error:
        failure = type(error).__name__
    finally:
        if guard is not None:
            try:
                try:
                    guard.stdin.write(b'restore\n')
                    guard.stdin.flush()
                except BrokenPipeError:
                    pass
                try:
                    guard.stdin.close()
                except BrokenPipeError:
                    pass
                report['guard_exit_status'] = guard.wait(timeout=35)
                guard.stdout.read()
                guard.stdout.close()
                restored = report['guard_exit_status'] == 0 and policy() == 1
            except Exception as error:
                failure = type(error).__name__
        else:
            try:
                restored = policy() == 1
            except Exception as error:
                failure = type(error).__name__
    try:
        if failure or not restored or not loaded or NAME not in modules():
            raise RuntimeError('Monitor startup not confirmed')
        def new_texts():
            texts = []
            for name, (inode, offset) in offsets.items():
                path = Path(name)
                stat = path.stat()
                if stat.st_ino != inode or stat.st_size < offset:
                    raise ValueError('Native log rotated during startup')
                with path.open('rb') as source:
                    source.seek(offset)
                    texts.append(source.read(256 * 1024).decode(errors='replace'))
            return texts
        report['sample'] = wait_for_sample(new_texts, reader['latest_sample'], time.time_ns, time.monotonic, time.sleep)
    except Exception as error:
        if loaded and restored:
            # Owned, reviewed artifact has a draining cleanup hook. Never force.
            try:
                cleanup = subprocess.run([LOADER, '-u', NAME], capture_output=True,
                    text=True, errors='replace', timeout=45)
                report['cleanup_returncode'] = cleanup.returncode
            except Exception as cleanup:
                report['cleanup_error'] = type(cleanup).__name__
        try:
            report['loaded'] = NAME in modules()
        except Exception as inventory:
            report['loaded'] = None
            report['inventory_error'] = type(inventory).__name__
        report.update(owned_load_confirmed=loaded, enforcement=1 if restored else None,
                      error=failure or type(error).__name__)
        print(json.dumps(report))
        return 1
    report.update(loaded=True, enforcement=1)
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    sys.exit(main())
