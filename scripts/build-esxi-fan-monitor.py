#!/usr/bin/env python3
"""Build/inspect the exact-build native monitor with an existing Clang, no DDK."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile


SOURCE = Path(__file__).resolve().parents[1] / 'src/monitor.c'
SOURCE_SHA = '18dab6a537bf35405f10baa4bd4c68b3a7c11a62c8ee8781221fcca3836ccc8b'
CORE = SOURCE.with_name('fan_core.h')
CORE_SHA = '8f3f4711964e5a9bb20441348a9b48e48b4d552d900d320958492321f2ecac49'
TRIALED_ARTIFACT = '6efcb75285b71135fadd0c26fa50fdeb2d81a097ebb3dd201d0b6e7180517fde'
KERNEL_SHA = '3c55688c314300ae90849b34959ad3dd5d66d2d5b14d3349a1204e470df9ac52'
FLAGS = ['--target=x86_64-unknown-linux-gnu', '-ffreestanding', '-O2',
         '-fno-stack-protector', '-fno-pic', '-fno-pie', '-mcmodel=large',
         '-mno-red-zone', '-mno-sse', '-mno-sse2', '-mno-mmx',
         '-fno-asynchronous-unwind-tables', '-fno-unwind-tables', '-fno-addrsig',
         '-std=c11', '-Wall', '-Wextra', '-Werror']
IMPORTS = {'_vmk_LogMessage', 'vmk_ModuleCurrentID', 'vmk_ACPIDeviceIterate',
           'vmk_ACPIQueryInfo', 'vmk_ACPIQueryIOResources', 'vmk_ModuleIncUseCount',
           'vmk_ModuleDecUseCount', 'vmk_ModuleGetHeapID', 'vmk_ModuleSetHeapID',
           'vmk_NameInitialize', 'vmk_HeapCreate', 'vmk_HeapDestroySync',
           'vmk_ACPIMapIOResource', 'vmk_ACPIUnmapIOResource', 'vmk_MappedResourceRead8',
           'vmk_WorldCreate', 'vmk_WorldSleep', 'vmk_WorldDestroy',
           'vmk_WorldWaitForDeath', 'vmk_WorldCreateAllocSize'}
METADATA = {'__vmk_licenseInfo_str': b'license=BSD\0',
            '__vmk_buildTypeInfo_str': b'buildType=release\0',
            '__vmk_versionInfo_str': b'version=0.0.1-fan-proof\0',
            '__vmk_nsRequiredInfo_str': b'nsRequired=com.vmware.vmkapi#v2_13_0_0\0'}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def inspect_elf(data: bytes) -> dict:
    require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01', 'Not little-endian ELF64')
    require(struct.unpack_from('<HH', data, 16) == (1, 62), 'Not x86-64 relocatable ELF')
    at = struct.unpack_from('<Q', data, 40)[0]
    width, count, ni = struct.unpack_from('<HHH', data, 58)
    require(width == 64 and 0 < count < 4096 and ni < count and at + width * count <= len(data), 'Invalid section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, at + i * width) for i in range(count)]
    for section in sections:
        require(not section[2] & 0x10000000, 'Unsupported large-section flag')
        require(section[1] == 8 or section[4] + section[5] <= len(data), 'Section exceeds object')
    s = sections[ni]
    names = data[s[4]:s[4] + s[5]]
    named = {names[s[0]:names.index(0, s[0])].decode(): s for s in sections}
    require('.eh_frame' not in named and '.llvm_addrsig' not in named, 'Unexpected runtime metadata')
    imports, exports, metadata, relocations = set(), set(), {}, set()
    for section in sections:
        if section[1] == 2:
            require(section[9] == 24 and section[6] < count, 'Invalid symbol table')
            strings_section = sections[section[6]]
            strings = data[strings_section[4]:strings_section[4] + strings_section[5]]
            for pos in range(section[4], section[4] + section[5], section[9]):
                n, info, other, index, value, size = struct.unpack_from('<IBBHQQ', data, pos)
                name = strings[n:strings.index(0, n)].decode()
                if name and not index:
                    imports.add(name)
                if index and info >> 4 in (1, 2):
                    require(info & 15 == 2, 'Unexpected exported data')
                    exports.add(name)
                if name in METADATA:
                    require(index < count and sections[index] == named.get('.vmkmodinfo'), 'Misplaced reserved metadata')
                    owner = sections[index]
                    metadata[name] = data[owner[4] + value:owner[4] + value + size]
        if section[1] == 4:
            require(section[9] == 24, 'Invalid relocation table')
            for pos in range(section[4], section[4] + section[5], section[9]):
                relocations.add(struct.unpack_from('<QQq', data, pos)[1] & 0xffffffff)
    require(imports == IMPORTS, 'Unexpected native imports')
    require(exports == {'init_module', 'cleanup_module'}, 'Unexpected native entrypoints')
    require(metadata == METADATA, 'Missing/incorrect reserved metadata')
    require(relocations <= {1, 2}, 'Unsupported or truncated-pointer relocation')
    return {'imports': sorted(imports), 'exports': sorted(exports), 'relocation_types': sorted(relocations)}


def build(output: Path, compiler: str) -> dict:
    output = Path(output)
    manifest_path = output.with_suffix(output.suffix + '.json')
    if output.exists() or manifest_path.exists():
        raise FileExistsError('Refusing to overwrite existing build output')
    require(hashlib.sha256(SOURCE.read_bytes()).hexdigest() == SOURCE_SHA, 'Source changed; review before updating its pin')
    require(hashlib.sha256(CORE.read_bytes()).hexdigest() == CORE_SHA, 'Core changed; review before updating its pin')
    objdump = shutil.which('objdump')
    require(bool(compiler and objdump), 'Existing Clang and objdump are required')
    with tempfile.TemporaryDirectory(dir=output.parent) as directory:
        first, second = Path(directory) / 'first.o', Path(directory) / 'second.o'
        for path in (first, second):
            subprocess.run([compiler, *FLAGS, '-c', str(SOURCE), '-o', str(path)], check=True, capture_output=True, text=True)
        data = first.read_bytes()
        require(data == second.read_bytes(), 'Independent builds are not byte-identical')
        inspected = inspect_elf(data)
        disassembly = subprocess.run([objdump, '-dr', str(first)], check=True, capture_output=True, text=True).stdout
        require(not re.search(r'%(?:xmm|ymm|zmm|mm)[0-9]', disassembly), 'Unexpected SIMD register use')
        require(not re.search(r'\s(?:inb|inw|inl|outb|outw|outl)\s', disassembly), 'Unexpected direct port I/O')
    digest = hashlib.sha256(data).hexdigest()
    manifest = dict(inspected, source_sha256=SOURCE_SHA, core_sha256=CORE_SHA, artifact_sha256=digest,
                    artifact_bytes=len(data), kernel_sha256=KERNEL_SHA,
                    byte_identical_rebuild=True, matches_trialed_artifact=digest == TRIALED_ARTIFACT)
    with output.open('xb') as target:
        target.write(data)
    with manifest_path.open('x') as target:
        json.dump(manifest, target, indent=2)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--compiler', default=shutil.which('clang'))
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.compiler)))


if __name__ == '__main__':
    main()
