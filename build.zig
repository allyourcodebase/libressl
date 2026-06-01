const std = @import("std");
const builtin = @import("builtin");
const gen = @import("generated.zig");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const tinfo = target.result;
    const optimize = b.standardOptimizeOption(.{});
    var build_asm = b.option(bool, "enable-asm", "Enable compiling assembly routines, if available (default: true)") orelse true;
    const openssl_dir = b.option([]const u8, "openssldir", "Set the default libressl configuration/certificate directory");
    const build_apps = b.option(bool, "build-apps", "Build the CLI programs nc, ocspcheck, and openssl (default: false)") orelse false;

    const upstream = b.dependency("libressl", .{});
    const libressl_common: LibreSslCommon = .{
        .libcrypto = b.addLibrary(.{
            .name = "crypto",
            .root_module = b.createModule(.{ .target = target, .optimize = optimize }),
        }),
        .libssl = b.addLibrary(.{
            .name = "ssl",
            .root_module = b.createModule(.{ .target = target, .optimize = optimize }),
        }),
        .libtls = b.addLibrary(.{
            .name = "tls",
            .root_module = b.createModule(.{ .target = target, .optimize = optimize }),
        }),
        .apps = .{
            .nc = b.addExecutable(.{
                .name = "nc",
                .root_module = b.createModule(.{ .target = target, .optimize = optimize }),
            }),
            .ocspcheck = b.addExecutable(.{
                .name = "ocspcheck",
                .root_module = b.createModule(.{ .target = target, .optimize = optimize }),
            }),
            .openssl = b.addExecutable(.{
                .name = "openssl",
                .root_module = b.createModule(.{ .target = target, .optimize = optimize }),
            }),
        },
    };

    libressl_common.linkLibC();

    const resolved_openssl_dir = if (openssl_dir) |dir|
        dir
    else if (tinfo.os.tag == .windows)
        "C:/Windows/libressl/ssl"
    else
        b.pathJoin(&.{ b.install_prefix, "etc", "ssl" });

    const common_cflags: []const []const u8 = &.{
        "-fno-sanitize=undefined",
        "-Wno-pointer-sign",
    };

    const cflags: []const []const u8 = switch (tinfo.os.tag) {
        .macos => common_cflags ++ .{"-fno-common"},
        else => common_cflags,
    };

    const crypto_srcroot = upstream.path("crypto");
    libressl_common.libcrypto.root_module.addCSourceFiles(.{
        .root = crypto_srcroot,
        .files = switch (tinfo.os.tag) {
            .windows => &gen.libcrypto_windows,
            else => &gen.libcrypto_unix,
        },
        .flags = cflags,
    });

    const ssl_srcroot = upstream.path("ssl");
    libressl_common.libssl.root_module.addCSourceFiles(.{
        .root = ssl_srcroot,
        .files = &gen.libssl_sources,
        .flags = cflags,
    });

    const tls_srcroot = upstream.path("tls");
    libressl_common.libtls.root_module.addCSourceFiles(.{
        .root = tls_srcroot,
        .files = switch (tinfo.os.tag) {
            .windows => &gen.libtls_windows,
            else => &gen.libtls_unix,
        },
        .flags = cflags,
    });

    const nc_srcroot = upstream.path("apps/nc");
    libressl_common.apps.nc.root_module.addCSourceFiles(.{
        .root = nc_srcroot,
        .files = nc_app_sources,
        .flags = cflags,
    });
    const ocspcheck_srcroot = upstream.path("apps/ocspcheck");
    libressl_common.apps.ocspcheck.root_module.addCSourceFiles(.{
        .root = ocspcheck_srcroot,
        .files = ocspcheck_app_sources,
        .flags = cflags,
    });
    const openssl_srcroot = upstream.path("apps/openssl");
    libressl_common.apps.openssl.root_module.addCSourceFiles(.{
        .root = openssl_srcroot,
        .files = openssl_app_sources,
        .flags = cflags,
    });

    // this logic is as similar as reasonable to the CMake logic:
    if (build_asm) {
        if (tinfo.ofmt == .elf) {
            if (tinfo.cpu.arch == .x86_64) {
                libressl_common.libcrypto.root_module.addCSourceFiles(.{
                    .root = crypto_srcroot,
                    .files = &gen.libcrypto_elf_x86_64_asm,
                    .flags = cflags,
                });

                libressl_common.libcrypto.root_module.addCMacro("AES_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("BSAES_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("VPAES_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("OPENSSL_IA32_SSE2", "");
                libressl_common.libcrypto.root_module.addCMacro("OPENSSL_BN_ASM_MONT", "");
                libressl_common.libcrypto.root_module.addCMacro("OPENSSL_BN_ASM_MONT5", "");
                libressl_common.libcrypto.root_module.addCMacro("MD5_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("GHASH_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("RSA_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("SHA1_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("SHA256_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("SHA512_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("WHIRLPOOL_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("OPENSSL_CPUID_OBJ", "");
                libressl_common.libcrypto.root_module.addCMacro("HAVE_GNU_STACK", "");
            } else if (tinfo.cpu.arch == .arm) {
                libressl_common.libcrypto.root_module.addCSourceFiles(.{
                    .root = crypto_srcroot,
                    .files = &gen.libcrypto_elf_armv4_asm,
                    .flags = cflags,
                });
                libressl_common.libcrypto.root_module.addCSourceFiles(.{
                    .root = crypto_srcroot,
                    .files = libcrypto_nonasm_or_armv4,
                    .flags = cflags,
                });

                libressl_common.libcrypto.root_module.addCMacro("AES_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("OPENSSL_BN_ASM_MONT", "");
                libressl_common.libcrypto.root_module.addCMacro("GHASH_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("SHA1_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("SHA256_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("SHA512_ASM", "");
                libressl_common.libcrypto.root_module.addCMacro("OPENSSL_CPUID_OBJ", "");
            } else {
                build_asm = false;
            }
        } else if (tinfo.os.tag.isDarwin() and tinfo.cpu.arch == .x86_64) {
            libressl_common.libcrypto.root_module.addCSourceFiles(.{
                .root = crypto_srcroot,
                .files = &gen.libcrypto_macos_x86_64_asm,
                .flags = cflags,
            });

            libressl_common.libcrypto.root_module.addCMacro("AES_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("BSAES_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("VPAES_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("OPENSSL_IA32_SSE2", "");
            libressl_common.libcrypto.root_module.addCMacro("OPENSSL_BN_ASM_MONT", "");
            libressl_common.libcrypto.root_module.addCMacro("OPENSSL_BN_ASM_MONT5", "");
            libressl_common.libcrypto.root_module.addCMacro("MD5_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("GHASH_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("RSA_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("SHA1_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("SHA256_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("SHA512_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("WHIRLPOOL_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("OPENSSL_CPUID_OBJ", "");
        } else if (tinfo.os.tag == .windows and tinfo.abi == .gnu) {
            libressl_common.libcrypto.root_module.addCSourceFiles(.{
                .root = crypto_srcroot,
                .files = &gen.libcrypto_mingw64_x86_64_asm,
                .flags = cflags,
            });
            libressl_common.libcrypto.root_module.addCMacro("AES_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("BSAES_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("VPAES_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("OPENSSL_IA32_SSE2", "");
            libressl_common.libcrypto.root_module.addCMacro("MD5_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("GHASH_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("RSA_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("SHA1_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("SHA256_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("SHA512_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("WHIRLPOOL_ASM", "");
            libressl_common.libcrypto.root_module.addCMacro("OPENSSL_CPUID_OBJ", "");
        } else {
            build_asm = false;
        }
    }
    if (!build_asm) {
        libressl_common.libcrypto.root_module.addCSourceFiles(.{
            .root = crypto_srcroot,
            .files = libcrypto_nonasm_or_armv4,
            .flags = cflags,
        });
        libressl_common.libcrypto.root_module.addCSourceFiles(.{
            .root = crypto_srcroot,
            .files = libcrypto_nonasm,
            .flags = cflags,
        });
        libressl_common.addCMacro("OPENSSL_NO_ASM", "");
    }

    libressl_common.addCMacro("OPENSSLDIR", std.fmt.allocPrint(b.allocator, "\"{s}\"", .{resolved_openssl_dir}) catch @panic("OOM"));
    libressl_common.addCMacro("LIBRESSL_INTERNAL", "");
    libressl_common.addCMacro("OPENSSL_NO_HW_PADLOCK", "");
    libressl_common.addCMacro("__BEGIN_HIDDEN_DECLS", "");
    libressl_common.addCMacro("__END_HIDDEN_DECLS", "");
    libressl_common.addCMacro("LIBRESSL_CRYPTO_INTERNAL", "");

    switch (tinfo.os.tag) {
        .linux => {
            libressl_common.apps.openssl.root_module.addCSourceFiles(.{
                .root = openssl_srcroot,
                .files = openssl_app_posix_sources,
                .flags = cflags,
            });

            libressl_common.addCMacro("_DEFAULT_SOURCE", "");
            libressl_common.addCMacro("_BSD_SOURCE", "");
            libressl_common.addCMacro("_POSIX_SOURCE", "");
            libressl_common.addCMacro("_GNU_SOURCE", "");

            libressl_common.addCMacro("HAVE_ASPRINTF", "");

            libressl_common.addCMacro("HAVE_STRCASECMP", "");

            libressl_common.addCMacro("HAVE_STRNDUP", "");
            libressl_common.addCMacro("HAVE_STRNLEN", "");
            libressl_common.addCMacro("HAVE_STRSEP", "");

            libressl_common.addCMacro("HAVE_EXPLICIT_BZERO", "");
            libressl_common.addCMacro("HAVE_GETAUXVAL", "");
            libressl_common.addCMacro("HAVE_GETPAGESIZE", "");

            libressl_common.addCMacro("HAVE_SYSLOG", "");
            libressl_common.addCMacro("HAVE_MEMMEM", "");
            libressl_common.addCMacro("HAVE_ENDIAN_H", "");
            libressl_common.addCMacro("HAVE_ERR_H", "");
            libressl_common.addCMacro("HAVE_NETINET_IP_H", "");

            if (tinfo.abi.isGnu()) {
                libressl_common.libcrypto.root_module.addCSourceFiles(.{
                    .root = crypto_srcroot,
                    .files = &gen.libcompat_linux_glibc_2_36,
                    .flags = cflags,
                });
            } else if (tinfo.abi.isMusl()) {
                libressl_common.libcrypto.root_module.addCSourceFiles(.{
                    .root = crypto_srcroot,
                    .files = &gen.libcompat_linux_musl,
                    .flags = cflags,
                });

                libressl_common.addCMacro("HAVE_STRLCAT", "");
                libressl_common.addCMacro("HAVE_STRLCPY", "");
                libressl_common.addCMacro("HAVE_GETENTROPY", "");
            } else @panic("weird ABI, dude");

            libressl_common.linkSystemLibrary("pthread");
        },
        .windows => {
            if (build_apps) {
                std.debug.print("Building the apps for Windows targets is not currently supported.\n", .{});
                return error.Unsupported;
            }

            libressl_common.libcrypto.root_module.addCSourceFiles(.{
                .root = crypto_srcroot,
                .files = &gen.libcompat_windows,
                .flags = cflags,
            });

            libressl_common.apps.openssl.root_module.addCSourceFiles(.{
                .root = openssl_srcroot,
                .files = openssl_app_windows_sources,
                .flags = cflags,
            });

            if (tinfo.abi != .msvc) {
                libressl_common.addCMacro("_GNU_SOURCE", "");
                libressl_common.addCMacro("_POSIX", "");
                libressl_common.addCMacro("_POSIX_SOURCE", "");
                libressl_common.addCMacro("__USE_MINGW_ANSI_STDIO", "");
            }

            libressl_common.addCMacro("_CRT_SECURE_NO_WARNINGS", "");
            libressl_common.addCMacro("_CRT_DEPRECATED_NO_WARNINGS", "");
            libressl_common.addCMacro("_REENTRANT", "");
            libressl_common.addCMacro("_POSIX_THREAD_SAFE_FUNCTIONS", "");
            libressl_common.addCMacro("CPPFLAGS", "");
            libressl_common.addCMacro("NO_SYSLOG", "");
            libressl_common.addCMacro("NO_CRYPT", "");
            libressl_common.addCMacro("WIN32_LEAN_AND_MEAN", "");
            libressl_common.addCMacroForLibs("_WIN32_WINNT", "0x0600");

            libressl_common.addCMacro("HAVE_ASPRINTF", "");
            libressl_common.addCMacro("HAVE_STRCASECMP", "");
            libressl_common.addCMacro("HAVE_STRNLEN", "");
            libressl_common.addCMacro("HAVE_GETAUXVAL", "");

            libressl_common.addCMacro("HAVE_TIMESPECSUB", "");
            libressl_common.addCMacro("HAVE_MEMMEM", "");
            libressl_common.addCMacro("HAVE_MACHINE_ENDIAN_H", "");
            libressl_common.addCMacro("HAVE_READPASSPHRASE", "");
            libressl_common.addCMacro("HAVE_ACCEPT4", "");
            libressl_common.addCMacro("HAVE_NETINET_IP_H", "");

            libressl_common.linkSystemLibrary("ws2_32");
            libressl_common.linkSystemLibrary("bcrypt");
        },

        else => if (tinfo.os.tag.isDarwin()) {
            libressl_common.libcrypto.root_module.addCSourceFiles(.{
                .root = crypto_srcroot,
                .files = &gen.libcompat_darwin,
                .flags = cflags,
            });
            libressl_common.apps.openssl.root_module.addCSourceFiles(.{
                .root = openssl_srcroot,
                .files = openssl_app_posix_sources,
                .flags = cflags,
            });

            libressl_common.addCMacro("HAVE_CLOCK_GETTIME", "");
            libressl_common.addCMacro("HAVE_ASPRINTF", "");
            libressl_common.addCMacro("HAVE_STRCASECMP", "");
            libressl_common.addCMacro("HAVE_STRLCAT", "");
            libressl_common.addCMacro("HAVE_STRLCPY", "");
            libressl_common.addCMacro("HAVE_STRNDUP", "");
            libressl_common.addCMacro("HAVE_STRNLEN", "");
            libressl_common.addCMacro("HAVE_STRSEP", "");
            libressl_common.addCMacro("HAVE_STRTONUM", "");
            libressl_common.addCMacro("HAVE_ARC4RANDOM_BUF", "");
            libressl_common.addCMacro("HAVE_ARC4RANDOM_UNIFORM", "");
            libressl_common.addCMacro("HAVE_GETENTROPY", "");
            libressl_common.addCMacro("HAVE_GETPAGESIZE", "");
            libressl_common.addCMacro("HAVE_GETPROGNAME", "");
            libressl_common.addCMacro("HAVE_MEMMEM", "");
            libressl_common.addCMacro("HAVE_MACHINE_ENDIAN_H", "");
            libressl_common.addCMacro("HAVE_ERR_H", "");
            libressl_common.addCMacro("HAVE_NETINET_IP_H", "");

            if (tinfo.cpu.arch == .x86_64 and build_asm) {} else {}
        } else {
            @panic("unsupported target OS");
        },
    }

    const conf_header = upstream.path(switch (tinfo.cpu.arch) {
        .aarch64,
        .aarch64_be,
        => source_header_prefix ++ "arch/aarch64/opensslconf.h",
        .x86 => source_header_prefix ++ "arch/i386/opensslconf.h",
        .riscv64 => source_header_prefix ++ "arch/riscv64/opensslconf.h",
        .x86_64 => source_header_prefix ++ "arch/amd64/opensslconf.h",

        else => @panic("unsupported target CPU arch"),
    });

    libressl_common.libtls.installHeader(upstream.path("include/tls.h"), "tls.h");
    libressl_common.libssl.installHeader(conf_header, "openssl/opensslconf.h");
    libressl_common.libssl.installHeadersDirectory(upstream.path("include/openssl"), "openssl", .{});

    for (libcrypto_include_paths) |path| {
        libressl_common.libcrypto.root_module.addIncludePath(upstream.path(path));
        libressl_common.apps.nc.root_module.addIncludePath(upstream.path(path));
        libressl_common.apps.ocspcheck.root_module.addIncludePath(upstream.path(path));
        libressl_common.apps.openssl.root_module.addIncludePath(upstream.path(path));
    }

    for (libssl_include_paths) |path| {
        libressl_common.libssl.root_module.addIncludePath(upstream.path(path));
        libressl_common.apps.nc.root_module.addIncludePath(upstream.path(path));
        libressl_common.apps.ocspcheck.root_module.addIncludePath(upstream.path(path));
        libressl_common.apps.openssl.root_module.addIncludePath(upstream.path(path));
    }

    for (libtls_include_paths) |path| {
        libressl_common.libtls.root_module.addIncludePath(upstream.path(path));
        libressl_common.apps.nc.root_module.addIncludePath(upstream.path(path));
    }

    libressl_common.apps.nc.root_module.addIncludePath(upstream.path("apps/nc/compat"));

    switch (tinfo.cpu.arch) {
        .aarch64,
        .aarch64_be,
        => {
            libressl_common.libcrypto.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "bn/arch/aarch64"),
            );
            libressl_common.libcrypto.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "arch/aarch64"),
            );
            libressl_common.libssl.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "arch/aarch64"),
            );
        },
        .x86 => {
            libressl_common.libcrypto.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "bn/arch/i386"),
            );
            libressl_common.libcrypto.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "arch/i386"),
            );
            libressl_common.libssl.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "arch/i386"),
            );
        },
        .riscv64 => {
            libressl_common.libcrypto.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "bn/arch/riscv64"),
            );
            libressl_common.libcrypto.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "arch/riscv64"),
            );
            libressl_common.libssl.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "arch/riscv64"),
            );
        },
        .x86_64 => {
            libressl_common.libcrypto.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "bn/arch/amd64"),
            );
            libressl_common.libcrypto.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "arch/amd64"),
            );
            libressl_common.libssl.root_module.addIncludePath(
                upstream.path(libcrypto_src_prefix ++ "arch/amd64"),
            );
        },

        else => @panic("unsupported target CPU architecture"),
    }

    // Used internally when building the static libraries (the installed copy
    // of the header does not end up in the compiler's include paths).
    const copy_conf_header = b.addWriteFiles();
    _ = copy_conf_header.addCopyFile(conf_header, "openssl/opensslconf.h");
    libressl_common.libcrypto.step.dependOn(&copy_conf_header.step);
    libressl_common.libssl.step.dependOn(&copy_conf_header.step);
    libressl_common.libtls.step.dependOn(&copy_conf_header.step);

    const conf_header_dir = copy_conf_header.getDirectory();
    libressl_common.libcrypto.root_module.addIncludePath(conf_header_dir);
    libressl_common.libssl.root_module.addIncludePath(conf_header_dir);
    libressl_common.libtls.root_module.addIncludePath(conf_header_dir);

    libressl_common.libssl.root_module.linkLibrary(libressl_common.libcrypto);

    // cmake builds libtls with libcrypto and libssl symbols jammed into it, but
    // this does not.
    libressl_common.libtls.root_module.linkLibrary(libressl_common.libcrypto);
    libressl_common.libtls.root_module.linkLibrary(libressl_common.libssl);

    libressl_common.installLibraries(b);

    // weird hack here
    libressl_common.apps.nc.root_module.addCMacro("DEFAULT_CA_FILE", b.pathJoin(&.{ b.install_prefix, "etc", "ssl", "cert.pem" }));
    libressl_common.apps.ocspcheck.root_module.addCMacro("DEFAULT_CA_FILE", b.pathJoin(&.{ b.install_prefix, "etc", "ssl", "cert.pem" }));
    libressl_common.apps.nc.root_module.linkLibrary(libressl_common.libtls);
    libressl_common.apps.ocspcheck.root_module.linkLibrary(libressl_common.libtls);
    libressl_common.apps.openssl.root_module.linkLibrary(libressl_common.libssl);

    if (build_apps) {
        libressl_common.installApps(b, upstream);
    }
}

const LibreSslCommon = struct {
    libcrypto: *std.Build.Step.Compile,
    libssl: *std.Build.Step.Compile,
    libtls: *std.Build.Step.Compile,
    apps: struct {
        nc: *std.Build.Step.Compile,
        ocspcheck: *std.Build.Step.Compile,
        openssl: *std.Build.Step.Compile,
    },

    pub fn linkLibC(self: LibreSslCommon) void {
        self.libcrypto.root_module.link_libc = true;
        self.libssl.root_module.link_libc = true;
        self.libtls.root_module.link_libc = true;
    }

    pub fn linkSystemLibrary(self: LibreSslCommon, library: []const u8) void {
        self.libcrypto.root_module.linkSystemLibrary(library, .{});
        self.libssl.root_module.linkSystemLibrary(library, .{});
        self.libtls.root_module.linkSystemLibrary(library, .{});
    }

    pub fn addCMacroForLibs(self: LibreSslCommon, name: []const u8, value: []const u8) void {
        self.libcrypto.root_module.addCMacro(name, value);
        self.libssl.root_module.addCMacro(name, value);
        self.libtls.root_module.addCMacro(name, value);
    }

    pub fn addCMacro(self: LibreSslCommon, name: []const u8, value: []const u8) void {
        self.addCMacroForLibs(name, value);
        self.apps.nc.root_module.addCMacro(name, value);
        self.apps.ocspcheck.root_module.addCMacro(name, value);
        self.apps.openssl.root_module.addCMacro(name, value);
    }

    pub fn installLibraries(self: LibreSslCommon, b: *std.Build) void {
        b.installArtifact(self.libcrypto);
        b.installArtifact(self.libssl);
        b.installArtifact(self.libtls);
    }

    pub fn installApps(self: LibreSslCommon, b: *std.Build, upstream: *std.Build.Dependency) void {
        b.installArtifact(self.apps.nc);
        b.installArtifact(self.apps.ocspcheck);
        b.installArtifact(self.apps.openssl);
        b.getInstallStep().dependOn(&b.addInstallFile(upstream.path("cert.pem"), "etc/ssl/cert.pem").step);
        b.getInstallStep().dependOn(&b.addInstallFile(upstream.path("openssl.cnf"), "etc/ssl/openssl.cnf").step);
        b.getInstallStep().dependOn(&b.addInstallFile(upstream.path("x509v3.cnf"), "etc/ssl/x509v3.cnf").step);
    }

    pub fn installHeader(self: LibreSslCommon, source: std.Build.LazyPath, dest: []const u8) void {
        self.libcrypto.installHeader(source, dest);
        self.libssl.installHeader(source, dest);
        self.libtls.installHeader(source, dest);
    }
};

const SkipSpec = union(enum) {
    starts_with: []const u8,
    ends_with: []const u8,
};

const base_src_prefix = "./";
const libcrypto_src_prefix = base_src_prefix ++ "crypto/";
const source_header_prefix = base_src_prefix ++ "include/";
const libssl_src_prefix = base_src_prefix ++ "ssl/";
const libtls_src_prefix = base_src_prefix ++ "tls/";

// only used on nonasm builds
const libcrypto_nonasm: []const []const u8 = &.{};

const libcrypto_include_paths: []const []const u8 = &.{
    libcrypto_src_prefix,
    libcrypto_src_prefix ++ "asn1",
    libcrypto_src_prefix ++ "bio",
    libcrypto_src_prefix ++ "bn",
    libcrypto_src_prefix ++ "bytestring",
    libcrypto_src_prefix ++ "conf",
    libcrypto_src_prefix ++ "dh",
    libcrypto_src_prefix ++ "dsa",
    libcrypto_src_prefix ++ "curve25519",
    libcrypto_src_prefix ++ "ec",
    libcrypto_src_prefix ++ "ecdh",
    libcrypto_src_prefix ++ "ecdsa",
    libcrypto_src_prefix ++ "err",
    libcrypto_src_prefix ++ "evp",
    libcrypto_src_prefix ++ "hidden",
    libcrypto_src_prefix ++ "hmac",
    libcrypto_src_prefix ++ "lhash",
    libcrypto_src_prefix ++ "modes",
    libcrypto_src_prefix ++ "ocsp",
    libcrypto_src_prefix ++ "pkcs12",
    libcrypto_src_prefix ++ "rsa",
    libcrypto_src_prefix ++ "sha",
    libcrypto_src_prefix ++ "stack",
    libcrypto_src_prefix ++ "x509",

    // these are order-dependent and they have to go after the "hidden" directory
    // because the "openssl" include directory is masked inside the "hidden" directory
    // in the source tree. cool.
    source_header_prefix ++ "compat",
    source_header_prefix,
};

// these are used on armv4 with asm, or a nonasm build
const libcrypto_nonasm_or_armv4: []const []const u8 = &.{};

const libssl_include_paths: []const []const u8 = &.{
    libssl_src_prefix,
    libssl_src_prefix ++ "hidden",

    libcrypto_src_prefix[0 .. libcrypto_src_prefix.len - 1],
    libcrypto_src_prefix ++ "bio",

    // these are order-dependent and they have to go after the "hidden" directory
    // because the "openssl" include directory is masked inside the "hidden" directory
    // in the source tree. cool.
    source_header_prefix ++ "compat",
    source_header_prefix,
};

const libtls_include_paths: []const []const u8 = &.{
    libssl_src_prefix,
    source_header_prefix ++ "compat",
    source_header_prefix,
};

const nc_app_sources: []const []const u8 = &.{
    "atomicio.c",
    "netcat.c",
    "socks.c",
    "compat/socket.c",
    // don't bother doing feature checks for these
    "compat/accept4.c",
    "compat/base64.c",
    "compat/readpassphrase.c",
};

const ocspcheck_app_sources: []const []const u8 = &.{
    "http.c",
    "ocspcheck.c",
    // don't bother doing feature checks for this
    "compat/memmem.c",
};

const openssl_app_sources: []const []const u8 = &.{
    "apps.c",
    "asn1pars.c",
    "ca.c",
    "ciphers.c",
    "cms.c",
    "crl.c",
    "crl2p7.c",
    "dgst.c",
    "dh.c",
    "dhparam.c",
    "dsa.c",
    "dsaparam.c",
    "ec.c",
    "ecparam.c",
    "enc.c",
    "errstr.c",
    "gendh.c",
    "gendsa.c",
    "genpkey.c",
    "genrsa.c",
    "ocsp.c",
    "openssl.c",
    "passwd.c",
    "pkcs12.c",
    "pkcs7.c",
    "pkcs8.c",
    "pkey.c",
    "pkeyparam.c",
    "pkeyutl.c",
    "prime.c",
    "rand.c",
    "req.c",
    "rsa.c",
    "rsautl.c",
    "s_cb.c",
    "s_client.c",
    "s_server.c",
    "s_socket.c",
    "s_time.c",
    "sess_id.c",
    "smime.c",
    "speed.c",
    "ts.c",
    "verify.c",
    "version.c",
    "x509.c",
};

const openssl_app_posix_sources: []const []const u8 = &.{
    "apps_posix.c",
    "certhash.c",
};

// clock_gettime has existed on macOS since 10.12
// "compat/clock_gettime_osx.c",

const openssl_app_windows_sources: []const []const u8 = &.{
    "apps_win.c",
    "certhash_win.c",

    "compat/poll_win.c",
};
