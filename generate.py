import sys
from collections import defaultdict

def extractFileLists(reader, desired: set[str]):
    result = defaultdict(list)
    inside = None
    condition = []
    for line in map(str.strip, reader):
        if line and line[0] == '#':
            continue
        if inside:
            value = line
            dest = inside
            if value and value[-1] == '\\':
                value = value[:-1].strip()
            else:
                inside = None
            if value and value[:3] != '"$(':
                result[dest, tuple(sorted(condition))].append(value)
        else:
            if line == 'endif':
                condition.pop()
            elif line == 'else':
                if condition[-1][0] == '!':
                    condition[-1] = condition[-1][1:]
                else:
                    condition[-1] = '!' + condition[-1]
            elif line[:3] == 'if ':
                condition.append(line[3:])
            elif '=' in line:
                sep = '+=' if '+=' in line else '='
                assigned, value = map(str.strip, line.split(sep, 1))
                if assigned in desired:
                    if value and value[-1] == '\\':
                        inside = assigned
                        value = value[:-1].strip()
                    if value and value[:2] != '$(':
                        result[assigned, tuple(sorted(condition))].append(value)
    return result

def getFileList(fileLists: dict, name: str, conditions: set[str]) -> list[str]:
    result = []
    print('---', name, conditions)
    for (listName, conds), files in fileLists.items():
        if listName == name:
            take = True
            for cond in conds:
                if cond[0] == '!':
                    if cond[1:] in conditions:
                        take = False
                        break
                elif cond not in conditions:
                    take = False
            print(conds, take)
            if take:
                result += files
    return result

interest = {
    'ASM_ARM_ELF': 'libcrypto_elf_armv4_asm',
    'ASM_X86_64_ELF': 'libcrypto_elf_x86_64_asm',
    'ASM_X86_64_MACOSX': 'libcrypto_macos_x86_64_asm',
    'ASM_X86_64_MINGW64': 'libcrypto_mingw64_x86_64_asm',
    'libcrypto_la_SOURCES': 'libcrypto_sources',
    'libcompat_la_SOURCES': 'libcrypto_compat_sources',
}

# linux + glibc:
# - < 2.38: !HAVE_STRLCAT, !HAVE_STRLCPY (https://sourceware.org/pipermail/libc-alpha/2023-July/150524.html)
# - < 2.36: !HAVE_ARC4RANDOM_BUF (https://sourceware.org/pipermail/libc-alpha/2022-August/141193.html)
# - < 2.29: HAVE_REALLOCARRAY requires _GNU_SOURCE

# syslog_r: only mention I could find: https://www.ibm.com/docs/en/aix/7.3.0?topic=s-syslog-r-openlog-r-closelog-r-setlogmask-r-subroutine

# strnlen: POSIX.1
# strlcpy, strlcat: OpenBSD 2.4, FreeBSD 3.3, NetBSD 1.4.3
# strndup: glibc 2.0, FreeBSD 7.2, NetBSD 4.0, OpenBSD 4.8
# strsep: 4.4BSD
# asprintf: glibc, OpenBSD 2.3, FreeBSD 2.2, on linux requires _GNU_SOURCE
# getpagesize: 4.2BSD, SUSv1, on linux requires _DEFAULT_SOURCE
# strtonum: OpenBSD 3.6, NetBSD 8 in the _OPENBSD_SOURCE namespace
# getprogname: NetBSD 1.6, FreeBSD 4.4, OpenBSD 5.4
# freezero: OpenBSD 6.2, DragonFly 5.5
# reallocarray: glibc 2.26, OpenBSD 5.6, FreeBSD 11.0, NetBSD 8 in the _OPENBSD_SOURCE namespace, NetBSD 10, DragonFly 5.5
# recallocarray: OpenBSD 6.1, DragonFly 5.5
# timingsafe_bcmp: OpenBSD 4.9, FreeBSD 11.1, DragonFly 5.6
# timingsafe_memcmp: OpenBSD 5.6, FreeBSD 11.1, DragonFly 5.6
# arc4random_buf: OpenBSD 2.1, FreeBSD 8.0, NetBSD 10.0, glibc 2.36

common = {'HAVE_STRNLEN'}
not_windows = common | {'HAVE_STRNDUP', 'HAVE_STRSEP', 'HAVE_ASPRINTF', 'HAVE_GETPAGESIZE'}
bsd = not_windows | {'HAVE_STRLCAT', 'HAVE_STRLCPY', 'HAVE_STRTONUM', 'HAVE_GETPROGNAME', 'HAVE_REALLOCARRAY', 'HAVE_ARC4RANDOM_BUF'}

windows = common | {'HOST_WIN'}
openbsd = bsd | {'HOST_OPENBSD', 'HAVE_FREEZERO', 'HAVE_RECALLOCARRAY', 'HAVE_TIMINGSAFE_MEMCMP', 'HAVE_TIMINGSAFE_BCMP'}
netbsd = bsd | {'HOST_NETBSD'}
freebsd = bsd | {'HOST_FREEBSD', 'HAVE_TIMINGSAFE_MEMCMP', 'HAVE_TIMINGSAFE_BCMP'}
darwin = not_windows | {'HOST_DARWIN', 'HAVE_STRTONUM', 'HAVE_GETPROGNAME', 'HAVE_ARC4RANDOM_BUF'}
linux_glibc_2_29 = not_windows | {'HOST_LINUX', 'HAVE_REALLOCARRAY'}
linux_glibc_2_36 = linux_glibc_2_29 | {'HAVE_ARC4RANDOM_BUF'}
linux_glibc_2_38 = linux_glibc_2_36 | {'HAVE_STRLCAT', 'HAVE_STRLCPY'}

fileLists = extractFileLists(sys.stdin, interest.keys())
exported = {}
#exported['libcypto_not_windows'] = getFileList(fileLists, 'libcrypto_la_SOURCES', {})
#exported['libcypto_windows'] = getFileList(fileLists, 'libcrypto_la_SOURCES', windows)
exported['libcompat_netbsd'] = getFileList(fileLists, 'libcompat_la_SOURCES', netbsd)
exported['libcompat_openbsd'] = getFileList(fileLists, 'libcompat_la_SOURCES', openbsd)
exported['libcompat_freebsd'] = getFileList(fileLists, 'libcompat_la_SOURCES', freebsd)
exported['libcompat_darwin'] = getFileList(fileLists, 'libcompat_la_SOURCES', darwin)
exported['libcompat_windows'] = getFileList(fileLists, 'libcompat_la_SOURCES', windows)
exported['libcompat_linux_glibc_2_36'] = getFileList(fileLists, 'libcompat_la_SOURCES', linux_glibc_2_36)
exported['libcompat_linux_glibc_2_38'] = getFileList(fileLists, 'libcompat_la_SOURCES', linux_glibc_2_38)

for name, files in exported.items():
    print(name, file=sys.stderr)
    print('pub const ' + name + ' = .{')
    for f in files:
        print(f'    "{f}",')
    print('};')
