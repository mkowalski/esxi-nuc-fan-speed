#!/bin/python3
"""Read only the resident sampler's cached logs, never hardware or loader policy."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time


MARKER = 'nuc_fan_monitor: sample '
LOGS = ('/var/log/vmkernel.log', '/var/log/vmkwarning.log')
TAIL_BYTES = 256 * 1024
FIELDS = {'v', 'seq', 'status', 'valid', 'rpm', 'reads', 'attempt',
          'signature_ok', 'type', 'high', 'low', 'high_after'}
NATIVE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z[ \t]+'
    r'In\(182\)[ \t]+vmkernel:[ \t]+(?:cpu[0-9]+:[0-9]+\)[ \t]*)?'
    r'(?P<message>nuc_fan_monitor: .*?)$')


def require_forced_command(original: str, arguments: list) -> None:
    if original != 'read-fan' or arguments:
        raise ValueError('Only the fixed read-fan command is permitted')


def native_match(line: str):
    match = NATIVE.fullmatch(line)
    if not match:
        raise ValueError('Missing native informational sampler provenance')
    return match


def native_message(line: str) -> str:
    return native_match(line)['message']


def is_sample_candidate(line: str) -> bool:
    return bool(re.search(r'nuc_fan_monitor:\s*sample(?:\s|$)', line))


def timestamp_ns(line: str) -> int:
    match = native_match(line)
    instant = datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    return int(instant.timestamp()) * 1_000_000_000 + int((match[2] or '0').ljust(9, '0'))


def parse_fields(line: str) -> dict:
    message = line if line.startswith('nuc_fan_monitor:') else native_message(line)
    if not message.startswith(MARKER):
        raise ValueError('Incomplete or indirect sampler payload')
    payload = message[len(MARKER):]
    values = {}
    for token in payload.split():
        match = re.fullmatch(r'([a-z_]+)=(0x[0-9a-fA-F]+|[0-9]+)', token)
        if not match or match[1] in values:
            raise ValueError('Malformed or duplicate sampler field')
        values[match[1]] = int(match[2], 16 if match[2].startswith('0x') else 10)
    if set(values) != FIELDS:
        raise ValueError('Unexpected sampler schema')
    return values


def latest_sample(log_texts: list, now_ns: int) -> dict:
    candidates = []
    for text in log_texts:
        # Only the most recent observation in each sink is eligible. An error
        # or malformed last record must not cause fallback to an older success.
        line = next((line for line in reversed(text.splitlines()) if is_sample_candidate(line)), None)
        if line is not None:
            candidates.append((timestamp_ns(line), native_message(line)))
    if not candidates:
        raise ValueError('No sampler observation')
    acquired = max(item[0] for item in candidates)
    latest = {payload for stamp, payload in candidates if stamp == acquired}
    if len(latest) != 1:
        raise ValueError('Conflicting latest observations')
    if type(now_ns) is not int or not now_ns - 90_000_000_000 <= acquired <= now_ns + 2_000_000_000:
        raise ValueError('Stale or future sampler observation')
    values = parse_fields(latest.pop())
    if values['v'] != 1 or not 1 <= values['seq'] < 1 << 64:
        raise ValueError('Unsupported sampler version or sequence')
    if values['status'] != 0 or values['valid'] != 1:
        raise ValueError('Sampler reported failure')
    if values['signature_ok'] != 1 or values['type'] != 1:
        raise ValueError('Unvalidated fan identity')
    if values['attempt'] not in (1, 2, 3) or values['reads'] != 7 + 3 * values['attempt']:
        raise ValueError('Invalid sampling budget')
    high, low, after = (values[key] for key in ('high', 'low', 'high_after'))
    if not all(0 <= byte <= 255 for byte in (high, low, after)) or high != after:
        raise ValueError('Unstable or invalid raw RPM')
    if not 0 <= values['rpm'] < 65535 or values['rpm'] != (high << 8) | low:
        raise ValueError('Invalid RPM or sentinel')
    return {'version': 1, 'acquired_ns': acquired, 'sequence': values['seq'],
            'fan_rpm': values['rpm']}


def read_log_texts() -> list:
    texts = []
    for name in LOGS:
        path = Path(name)
        try:
            with path.open('rb') as source:
                size = os.fstat(source.fileno()).st_size
                source.seek(max(0, size - TAIL_BYTES))
                texts.append(source.read(TAIL_BYTES).decode('utf-8', errors='replace'))
        except FileNotFoundError:
            continue
    return texts


def main() -> int:
    try:
        require_forced_command(os.environ.get('SSH_ORIGINAL_COMMAND'), sys.argv[1:])
        sample = latest_sample(read_log_texts(), time.time_ns())
    except (ValueError, OSError) as error:
        print(json.dumps({'version': 1, 'success': False, 'reason': type(error).__name__}))
        return 1
    print(json.dumps(sample, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
