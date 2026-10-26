# ESXi NUC fan speed

Reads measured CPU-fan RPM on an Intel NUC using a native ESXi module. Samples
every 30 seconds; a Python reader returns the latest validated sample as JSON.
No VMware DDK or additional Python packages are required.

## Supported target

**NUC11TNHi5 / i5-1135G7**, BIOS `TNTGL357.0080`, **ESXi 8.0.3 U3j build 25429389**.
This experimental module uses private, build-specific interfaces. Other hardware
or kernel builds require fresh validation; successful compilation is not enough.

## Build and test

Requires Python 3, Clang with x86-64 ELF support, `objdump`, and a POSIX C/pthread
environment for native tests. Tests use `/usr/bin/clang`.

```sh
python3 -B -m unittest discover -s tests -v
mkdir -p build
python3 scripts/build-esxi-fan-monitor.py --compiler /usr/bin/clang --output build/nuc_fan_monitor.o
```

The builder checks reproducibility, ELF metadata, imports, relocations and
instructions. It refuses to overwrite output. The qualified 19,088-byte ELF has
SHA-256 `6efcb75285b71135fadd0c26fa50fdeb2d81a097ebb3dd201d0b6e7180517fde`.
A different compiler's output is not automatically safe to load.

## Read RPM

On the supported host, stage the built object, `scripts/esxi-fan-start.py` and
`scripts/esxi-fan-reader.py` in `/vmfs/volumes/datastore1/monitoring/`. Use a
root-owned directory and files, mode `0700`. Do not overwrite a running module.

```sh
/bin/python3 -I -B /vmfs/volumes/datastore1/monitoring/esxi-fan-start.py
SSH_ORIGINAL_COMMAND=read-fan /bin/python3 -I /vmfs/volumes/datastore1/monitoring/esxi-fan-reader.py
```

```json
{"version":1,"acquired_ns":1793019518123456789,"sequence":20,"fan_rpm":3125}
```

The loader pins the kernel, module and reader, restores execution enforcement
before reporting success, and requires a new valid sample. It refuses an existing
module. The cached reader accepts no arguments, preserves native timestamps and
rejects errors, malformed latest records, samples older than 90 seconds and future
timestamps beyond 2 seconds. `SSH_ORIGINAL_COMMAND` is not authentication.

## Safety

- Hardware operations are read-only, but the whole 6 MiB resource mapping is
  read-write/uncached. At most 16 byte reads occur per cycle. Matching high bytes
  do not guarantee an atomic EC update. No concurrent PRRE lifecycle operation.
- Effective `/User/ExecInstalledOnly` starts and ends at 1. Only loading uses a
  bounded, serialized temporary exception. Kernel boot `execInstalledOnly` and
  `preventFreePageMapping` must be runtime FALSE; do not disable new protections
  to make another kernel load.
- Normal removal: `/bin/vmkload_mod -u nuc_fan_monitor`; allow at least 45 seconds.
  **Never force unload.** Failed cleanup can retain a pin or block teardown;
  stop and investigate rather than repeatedly retrying. This is containment,
  not automatic recovery. No boot-persistence or reboot validation is provided.
