#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12"
# ///

# To check type correctness:
# uvx ty check generate.py

import sys
from collections import defaultdict
from typing import TextIO

type FileListMap = dict[str, dict[tuple[str, ...], list[str]]]

# Parse Makfile syntax to extract the value of variables in _desired_, if present
# Values appended within a 'if' block are stored in separate entries
#
# Sample input:
# if !HAVE_GETPROGNAME
# if HOST_LINUX
# libcompat_la_SOURCES += compat/getprogname_linux.c
# else
# if HOST_WIN
# libcompat_la_SOURCES += compat/getprogname_windows.c
# else
# libcompat_la_SOURCES += compat/getprogname_unimpl.c
# endif
# endif
# endif
#
# Sample output:
# {
#     'libcompat_la_SOURCES': {
#         ('!HAVE_GETPROGNAME', 'HOST_LINUX'): ['compat/getprogname_linux.c'],
#         ('!HAVE_GETPROGNAME', '!HOST_LINUX', 'HOST_WIN'): ['compat/getprogname_windows.c'],
#         ('!HAVE_GETPROGNAME', '!HOST_LINUX', '!HOST_WIN'): ['compat/getprogname_unimpl.c'],
#     }
# }
def extract_file_lists(reader: TextIO, desired: set[str]) -> FileListMap:
    result: FileListMap = defaultdict(lambda: defaultdict(list))
    current_variable: str | None = None
    condition_stack: list[str] = []
    for line in map(str.strip, reader):
        if not line or line[0] == '#':
            continue
        if current_variable:
            value = line
            dest = current_variable
            if value and value[-1] == '\\':
                value = value[:-1].strip()
            else:
                current_variable = None
            if value:
                result[dest][tuple(sorted(condition_stack))].append(value)
        else:
            if line == 'endif':
                condition_stack.pop()
            elif line == 'else':
                if condition_stack[-1][0] == '!':
                    condition_stack[-1] = condition_stack[-1][1:]
                else:
                    condition_stack[-1] = '!' + condition_stack[-1]
            elif line[:3] == 'if ':
                condition_stack.append(line[3:])
            elif '=' in line:
                sep = '+=' if '+=' in line else '='
                assigned, value = map(str.strip, line.split(sep, 1))
                if assigned in desired:
                    if value and value[-1] == '\\':
                        current_variable = assigned
                        value = value[:-1].strip()
                    if value:
                        result[assigned][tuple(sorted(condition_stack))].append(value)
    return result

# Get the value of a given variable, given a configuration
def get_file_list(file_lists: FileListMap, name: str, situation: set[str]) -> list[str]:
    result: list[str] = []
    for conditions, files in file_lists[name].items():
        take: bool = True
        for cond in conditions:
            if cond[0] == '!':
                if cond[1:] in situation:
                    take = False
                    break
            elif cond not in situation:
                take = False
                break
        if take:
            result += files
    return result

interest = {
    'ASM_ARM_ELF': 'libcrypto_elf_armv4_asm',
    'ASM_X86_64_ELF': 'libcrypto_elf_x86_64_asm',
    'ASM_X86_64_MACOSX': 'libcrypto_macos_x86_64_asm',
    'ASM_X86_64_MINGW64': 'libcrypto_mingw64_x86_64_asm',
    'libcrypto_la_SOURCES': None,
    'libcompat_la_SOURCES': None,
    'libtls_la_SOURCES': None,
    'libssl_la_SOURCES': None,
}

# syslog_r: only mention I could find: https://www.ibm.com/docs/en/aix/7.3.0?topic=s-syslog-r-openlog-r-closelog-r-setlogmask-r-subroutine

# strnlen: POSIX.1
# strlcpy, strlcat: OpenBSD 2.4, FreeBSD 3.3, NetBSD 1.4.3, glibc 2.38
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
# getentropy: OpenBSD 5.6, FreeBSD 12.0, NetBSD 10.0, POSIX.1-2024
# getdelim, getline: POSIX.1, FreeBSD 8.0, OpenBSD 5.2, NetBSD 6.0
# ftruncate: 4.2BSD

common = {'HAVE_STRNLEN'}
not_windows = common | {'HAVE_STRNDUP', 'HAVE_STRSEP', 'HAVE_ASPRINTF', 'HAVE_GETPAGESIZE', 'HAVE_GETENTROPY', 'HAVE_GETDELIM', 'HAVE_GETLINE', 'HAVE_FTRUNCATE'}
old_bsd = not_windows | {'HAVE_STRLCAT', 'HAVE_STRLCPY', 'HAVE_STRTONUM', 'HAVE_GETPROGNAME', 'HAVE_ARC4RANDOM_BUF'}
bsd = old_bsd | {'HAVE_REALLOCARRAY'}

windows = common | {'HOST_WIN'}
openbsd = bsd | {'HOST_OPENBSD', 'HAVE_FREEZERO', 'HAVE_RECALLOCARRAY', 'HAVE_TIMINGSAFE_MEMCMP', 'HAVE_TIMINGSAFE_BCMP'}
netbsd = bsd | {'HOST_NETBSD'}
freebsd = bsd | {'HOST_FREEBSD', 'HAVE_TIMINGSAFE_MEMCMP', 'HAVE_TIMINGSAFE_BCMP'}
darwin = old_bsd | {'HOST_DARWIN'}
linux_glibc_2_26 = not_windows | {'HOST_LINUX', 'HAVE_REALLOCARRAY'}
linux_glibc_2_36 = linux_glibc_2_26 | {'HAVE_ARC4RANDOM_BUF'}
linux_glibc_2_38 = linux_glibc_2_36 | {'HAVE_STRLCAT', 'HAVE_STRLCPY'}
linux_musl = linux_glibc_2_38

file_lists = extract_file_lists(sys.stdin, set(interest.keys()))
exported = {}
exported['libcrypto_unix'] = get_file_list(file_lists, 'libcrypto_la_SOURCES', set())
exported['libcrypto_windows'] = get_file_list(file_lists, 'libcrypto_la_SOURCES', windows)
#exported['libcompat_netbsd'] = get_file_list(file_lists, 'libcompat_la_SOURCES', netbsd)
#exported['libcompat_openbsd'] = get_file_list(file_lists, 'libcompat_la_SOURCES', openbsd)
#exported['libcompat_freebsd'] = get_file_list(file_lists, 'libcompat_la_SOURCES', freebsd)
exported['libcompat_darwin'] = get_file_list(file_lists, 'libcompat_la_SOURCES', darwin)
exported['libcompat_windows'] = get_file_list(file_lists, 'libcompat_la_SOURCES', windows)
exported['libcompat_linux_glibc_2_36'] = get_file_list(file_lists, 'libcompat_la_SOURCES', linux_glibc_2_36)
exported['libcompat_linux_glibc_2_38'] = get_file_list(file_lists, 'libcompat_la_SOURCES', linux_glibc_2_38)
exported['libcompat_linux_musl'] = get_file_list(file_lists, 'libcompat_la_SOURCES', linux_musl)
exported['libtls_windows'] = get_file_list(file_lists, 'libtls_la_SOURCES', windows)
exported['libtls_unix'] = get_file_list(file_lists, 'libtls_la_SOURCES', set())
exported['libssl_sources'] = get_file_list(file_lists, 'libssl_la_SOURCES', set())

for key, value in interest.items():
    if value is None:
        continue
    exported[value] = get_file_list(file_lists, key, set())

for name, files in exported.items():
    print(name, file=sys.stderr)
    print('pub const ' + name + ' = .{')
    for f in files:
        print(f'    "{f}",')
    print('};')
