import sys
from collections import defaultdict

def lines():
    while True:
        try:
            yield input()
        except:
            break

def extractFileLists(reader, desired: set[str]):
    result = defaultdict(list)
    inside = None
    for line in map(str.strip, reader):
        if line and line[0] == '#':
            continue
        if inside is None and '=' in line:
            sep = '+=' if '+=' in line else '='
            assigned, value = map(str.strip, line.split(sep, 1))
            if assigned in desired:
                if value and value[-1] == '\\':
                    inside = assigned
                    value = value[:-1].strip()
                if value:
                    result[assigned].append(value)
        elif inside:
            value = line
            dest = inside
            if value and value[-1] == '\\':
                value = value[:-1].strip()
            else:
                inside = None
            if value:
                result[dest].append(value)
    return result

interest = {
    'ASM_ARM_ELF': 'libcrypto_elf_armv4_asm',
    'ASM_X86_64_ELF': 'libcrypto_elf_x86_64_asm',
    'ASM_X86_64_MACOSX': 'libcrypto_macos_x86_64_asm',
    'ASM_X86_64_MINGW64': 'libcrypto_mingw64_x86_64_asm',
}

fileLists = extractFileLists(lines(), interest.keys())

exported = {v: fileLists[k] for k, v in interest.items()}

for name, files in exported.items():
    print(name, file=sys.stderr)
    print('pub const ' + name + ' = .{')
    for f in files:
        print(f'    "{f}",')
    print('};')
