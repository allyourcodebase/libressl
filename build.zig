const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const upstream = b.dependency("libressl", .{});

    const libressl_libs: LibreSslLibs = .{
        .libcrypto = b.addStaticLibrary(.{
            .name = "cypto",
            .target = target,
            .optimize = optimize,
        }),

        .libssl = b.addStaticLibrary(.{
            .name = "ssl",
            .target = target,
            .optimize = optimize,
        }),

        .libtls = b.addStaticLibrary(.{
            .name = "tls",
            .target = target,
            .optimize = optimize,
        }),
    };

    libressl_libs.linkLibC();

    const tinfo = target.result;

    const common_cflags: []const []const u8 = &.{
        "-Wno-pointer-sign",
    };

    const cflags: []const []const u8 = switch (tinfo.os.tag) {
        .macos => common_cflags ++ .{"-fno-common"},
        else => common_cflags,
    };

    const crypto_srcroot = upstream.path("crypto");
    libressl_libs.libcrypto.addCSourceFiles(.{
        .root = crypto_srcroot,
        .files = &libcrypto_sources,
        .flags = cflags,
    });
    libressl_libs.libcrypto.addCSourceFiles(.{
        .root = crypto_srcroot,
        .files = &libcrypto_nonasm,
        .flags = cflags,
    });
    libressl_libs.libcrypto.addCSourceFiles(.{
        .root = crypto_srcroot,
        .files = &libcrypto_nonasm_or_armv4,
        .flags = cflags,
    });

    const ssl_srcroot = upstream.path("ssl");
    libressl_libs.libssl.addCSourceFiles(.{
        .root = ssl_srcroot,
        .files = &libssl_sources,
        .flags = cflags,
    });

    const tls_srcroot = upstream.path("tls");
    libressl_libs.libtls.addCSourceFiles(.{
        .root = tls_srcroot,
        .files = &libtls_sources,
        .flags = cflags,
    });

    libressl_libs.defineCMacro("LIBRESSL_INTERNAL", null);
    libressl_libs.defineCMacro("OPENSSL_NO_HW_PADLOCK", null);
    libressl_libs.defineCMacro("__BEGIN_HIDDEN_DECLS", "");
    libressl_libs.defineCMacro("__END_HIDDEN_DECLS", "");
    libressl_libs.defineCMacro("LIBRESSL_CRYPTO_INTERNAL", null);
    libressl_libs.defineCMacro("OPENSSL_NO_ASM", null);

    switch (tinfo.os.tag) {
        .macos => {
            libressl_libs.libcrypto.addCSourceFiles(.{
                .root = crypto_srcroot,
                .files = &libcrypto_unix_sources,
                .flags = cflags,
            });
            libressl_libs.libcrypto.addCSourceFiles(.{
                .root = crypto_srcroot,
                .files = &libcrypto_macos_compat,
                .flags = cflags,
            });

            libressl_libs.defineCMacro("HAVE_CLOCK_GETTIME", null);
            libressl_libs.defineCMacro("HAVE_ASPRINTF", null);
            libressl_libs.defineCMacro("HAVE_STRCASECMP", null);
            libressl_libs.defineCMacro("HAVE_STRLCAT", null);
            libressl_libs.defineCMacro("HAVE_STRLCPY", null);
            libressl_libs.defineCMacro("HAVE_STRNDUP", null);
            libressl_libs.defineCMacro("HAVE_STRNLEN", null);
            libressl_libs.defineCMacro("HAVE_STRSEP", null);
            libressl_libs.defineCMacro("HAVE_STRTONUM", null);
            libressl_libs.defineCMacro("HAVE_TIMEGM", null);
            libressl_libs.defineCMacro("HAVE_ARC4RANDOM_BUF", null);
            libressl_libs.defineCMacro("HAVE_ARC4RANDOM_UNIFORM", null);
            libressl_libs.defineCMacro("HAVE_GETENTROPY", null);
            libressl_libs.defineCMacro("HAVE_GETPAGESIZE", null);
            libressl_libs.defineCMacro("HAVE_GETPROGNAME", null);
            libressl_libs.defineCMacro("HAVE_MEMMEM", null);
            libressl_libs.defineCMacro("HAVE_MACHINE_ENDIAN_H", null);
            libressl_libs.defineCMacro("HAVE_ERR_H", null);
            libressl_libs.defineCMacro("HAVE_NETINET_IP_H", null);

            if (tinfo.cpu.arch == .x86_64) {
                libressl_libs.libcrypto.addCSourceFiles(.{
                    .root = crypto_srcroot,
                    .files = &libcrypto_macos_amd64_asm,
                    .flags = cflags,
                });

                libressl_libs.libcrypto.defineCMacro("AES_ASM", null);
                libressl_libs.libcrypto.defineCMacro("BSAES_ASM", null);
                libressl_libs.libcrypto.defineCMacro("VPAES_ASM", null);
                libressl_libs.libcrypto.defineCMacro("OPENSSL_IA32_SSE2", null);
                libressl_libs.libcrypto.defineCMacro("OPENSSL_BN_ASM_MONT", null);
                libressl_libs.libcrypto.defineCMacro("OPENSSL_BN_ASM_MONT5", null);
                libressl_libs.libcrypto.defineCMacro("MD5_ASM", null);
                libressl_libs.libcrypto.defineCMacro("GHASH_ASM", null);
                libressl_libs.libcrypto.defineCMacro("RSA_ASM", null);
                libressl_libs.libcrypto.defineCMacro("SHA1_ASM", null);
                libressl_libs.libcrypto.defineCMacro("SHA256_ASM", null);
                libressl_libs.libcrypto.defineCMacro("SHA512_ASM", null);
                libressl_libs.libcrypto.defineCMacro("WHIRLPOOL_ASM", null);
                libressl_libs.libcrypto.defineCMacro("OPENSSL_CPUID_OBJ", null);
            }
        },
        .linux => {
            libressl_libs.libcrypto.addCSourceFiles(.{
                .root = crypto_srcroot,
                .files = &libcrypto_unix_sources,
                .flags = cflags,
            });
            libressl_libs.libcrypto.addCSourceFiles(.{
                .root = crypto_srcroot,
                .files = &libcrypto_linux_compat,
                .flags = cflags,
            });

            libressl_libs.defineCMacro("_DEFAULT_SOURCE", null);
            libressl_libs.defineCMacro("_BSD_SOURCE", null);
            libressl_libs.defineCMacro("_POSIX_SOURCE", null);
            libressl_libs.defineCMacro("_GNU_SOURCE", null);

            libressl_libs.defineCMacro("HAVE_ASPRINTF", null);

            libressl_libs.defineCMacro("HAVE_STRCASECMP", null);

            libressl_libs.defineCMacro("HAVE_STRNDUP", null);
            libressl_libs.defineCMacro("HAVE_STRNLEN", null);
            libressl_libs.defineCMacro("HAVE_STRSEP", null);
            libressl_libs.defineCMacro("HAVE_TIMEGM", null);

            libressl_libs.defineCMacro("HAVE_EXPLICIT_BZERO", null);
            libressl_libs.defineCMacro("HAVE_GETAUXVAL", null);
            libressl_libs.defineCMacro("HAVE_GETPAGESIZE", null);

            libressl_libs.defineCMacro("HAVE_SYSLOG", null);
            libressl_libs.defineCMacro("HAVE_TIMESPECSUB", null);
            libressl_libs.defineCMacro("HAVE_MEMMEM", null);
            libressl_libs.defineCMacro("HAVE_ENDIAN_H", null);
            libressl_libs.defineCMacro("HAVE_ERR_H", null);
            libressl_libs.defineCMacro("HAVE_NETINET_IP_H", null);

            if (tinfo.abi.isGnu()) {
                libressl_libs.libcrypto.addCSourceFiles(.{
                    .root = crypto_srcroot,
                    .files = &libcrypto_linux_glibc_compat,
                    .flags = cflags,
                });
            } else if (tinfo.abi.isMusl()) {
                libressl_libs.libcrypto.addCSourceFiles(.{
                    .root = crypto_srcroot,
                    .files = &libcrypto_linux_musl_compat,
                    .flags = cflags,
                });

                libressl_libs.defineCMacro("HAVE_STRLCAT", null);
                libressl_libs.defineCMacro("HAVE_STRLCPY", null);
                libressl_libs.defineCMacro("HAVE_GETENTROPY", null);
            } else @panic("weird ABI, dude");

            libressl_libs.linkSystemLibrary("pthread");
        },
        .windows => {
            libressl_libs.libcrypto.addCSourceFiles(.{
                .root = crypto_srcroot,
                .files = &libcrypto_windows_sources,
                .flags = cflags,
            });
            libressl_libs.libcrypto.addCSourceFiles(.{
                .root = crypto_srcroot,
                .files = &libcrypto_windows_compat,
                .flags = cflags,
            });
            libressl_libs.libtls.addCSourceFiles(.{
                .root = tls_srcroot,
                .files = &libtls_windows_sources,
                .flags = cflags,
            });

            if (tinfo.abi != .msvc) {
                libressl_libs.defineCMacro("_GNU_SOURCE", null);
                libressl_libs.defineCMacro("_POSIX", null);
                libressl_libs.defineCMacro("_POSIX_SOURCE", null);
                libressl_libs.defineCMacro("__USE_MINGW_ANSI_STDIO", null);
            }

            libressl_libs.defineCMacro("_CRT_SECURE_NO_WARNINGS", null);
            libressl_libs.defineCMacro("_CRT_DEPRECATED_NO_WARNINGS", null);
            libressl_libs.defineCMacro("_REENTRANT", null);
            libressl_libs.defineCMacro("_POSIX_THREAD_SAFE_FUNCTIONS", null);
            libressl_libs.defineCMacro("CPPFLAGS", null);
            libressl_libs.defineCMacro("NO_SYSLOG", null);
            libressl_libs.defineCMacro("NO_CRYPT", null);
            libressl_libs.defineCMacro("WIN32_LEAN_AND_MEAN", null);
            libressl_libs.defineCMacro("_WIN32_WINNT", "0x0600");

            libressl_libs.defineCMacro("HAVE_ASPRINTF", null);
            libressl_libs.defineCMacro("HAVE_STRCASECMP", null);
            libressl_libs.defineCMacro("HAVE_STRNLEN", null);
            libressl_libs.defineCMacro("HAVE_GETAUXVAL", null);

            libressl_libs.defineCMacro("HAVE_TIMESPECSUB", null);
            libressl_libs.defineCMacro("HAVE_MEMMEM", null);
            libressl_libs.defineCMacro("HAVE_MACHINE_ENDIAN_H", null);
            libressl_libs.defineCMacro("HAVE_ERR_H", null);
            libressl_libs.defineCMacro("HAVE_NETINET_IP_H", null);

            libressl_libs.linkSystemLibrary("ws2_32");
            libressl_libs.linkSystemLibrary("bcrypt");
        },

        else => @panic("unsupported target OS"),
    }

    const conf_header = upstream.path(switch (tinfo.cpu.arch) {
        .aarch64,
        .aarch64_be,
        .aarch64_32,
        => source_header_prefix ++ "arch/aarch64/opensslconf.h",
        .x86 => source_header_prefix ++ "arch/i386/opensslconf.h",
        .riscv64 => source_header_prefix ++ "arch/riscv64/opensslconf.h",
        .x86_64 => source_header_prefix ++ "arch/amd64/opensslconf.h",

        else => @panic("unsupported target CPU arch"),
    });

    libressl_libs.installHeader(conf_header, "openssl/opensslconf.h");

    try libressl_libs.header_search(
        b,
        upstream,
        source_header_prefix,
        &.{
            .{ .starts_with = "compat" },
            .{ .starts_with = "arch" },
            .{ .ends_with = "pqueue.h" },
        },
    );

    for (libcrypto_include_paths) |path| {
        libressl_libs.libcrypto.addIncludePath(upstream.path(path));
    }

    for (libssl_include_paths) |path| {
        libressl_libs.libssl.addIncludePath(upstream.path(path));
    }

    for (libtls_include_paths) |path| {
        libressl_libs.libtls.addIncludePath(upstream.path(path));
    }

    switch (tinfo.cpu.arch) {
        .aarch64,
        .aarch64_be,
        .aarch64_32,
        => libressl_libs.libcrypto.addIncludePath(
            upstream.path(libcrypto_src_prefix ++ "bn/arch/aarch64"),
        ),
        .x86 => libressl_libs.libcrypto.addIncludePath(
            upstream.path(libcrypto_src_prefix ++ "bn/arch/i386"),
        ),
        .riscv64 => libressl_libs.libcrypto.addIncludePath(
            upstream.path(libcrypto_src_prefix ++ "bn/arch/riscv64"),
        ),
        .x86_64 => libressl_libs.libcrypto.addIncludePath(
            upstream.path(libcrypto_src_prefix ++ "bn/arch/amd64"),
        ),

        else => @panic("unsupported target CPU architecture"),
    }

    // Used internally when building the static libraries (the installed copy
    // of the header does not end up in the compiler's include paths).
    const copy_conf_header = b.addWriteFiles();
    _ = copy_conf_header.addCopyFile(conf_header, "openssl/opensslconf.h");
    libressl_libs.libcrypto.step.dependOn(&copy_conf_header.step);
    libressl_libs.libssl.step.dependOn(&copy_conf_header.step);
    libressl_libs.libtls.step.dependOn(&copy_conf_header.step);

    const conf_header_dir = copy_conf_header.getDirectory();
    libressl_libs.libcrypto.addIncludePath(conf_header_dir);
    libressl_libs.libssl.addIncludePath(conf_header_dir);
    libressl_libs.libtls.addIncludePath(conf_header_dir);

    libressl_libs.libssl.linkLibrary(libressl_libs.libcrypto);

    // cmake builds libtls with libcrypto and libssl symbols jammed into it, but
    // this does not.
    libressl_libs.libtls.linkLibrary(libressl_libs.libcrypto);
    libressl_libs.libtls.linkLibrary(libressl_libs.libssl);

    libressl_libs.installArtifact(b);
}

const LibreSslLibs = struct {
    libcrypto: *std.Build.Step.Compile,
    libssl: *std.Build.Step.Compile,
    libtls: *std.Build.Step.Compile,

    pub fn linkLibC(self: LibreSslLibs) void {
        self.libcrypto.linkLibC();
        self.libssl.linkLibC();
        self.libtls.linkLibC();
    }

    pub fn linkSystemLibrary(self: LibreSslLibs, library: []const u8) void {
        self.libcrypto.linkSystemLibrary(library);
        self.libssl.linkSystemLibrary(library);
        self.libtls.linkSystemLibrary(library);
    }

    pub fn defineCMacro(self: LibreSslLibs, name: []const u8, value: ?[]const u8) void {
        self.libcrypto.defineCMacro(name, value);
        self.libssl.defineCMacro(name, value);
        self.libtls.defineCMacro(name, value);
    }

    pub fn installArtifact(self: LibreSslLibs, b: *std.Build) void {
        b.installArtifact(self.libcrypto);
        b.installArtifact(self.libssl);
        b.installArtifact(self.libtls);
    }

    pub fn installHeader(self: LibreSslLibs, source: std.Build.LazyPath, dest: []const u8) void {
        self.libcrypto.installHeader(source, dest);
        self.libssl.installHeader(source, dest);
        self.libtls.installHeader(source, dest);
    }

    pub fn header_search(
        self: LibreSslLibs,
        b: *std.Build,
        upstream: *std.Build.Dependency,
        base: []const u8,
        skiplist: []const SkipSpec,
    ) !void {
        const dir = try upstream.builder.build_root.handle.openDir(base, .{ .iterate = true });
        var walker = try dir.walk(b.allocator);
        defer walker.deinit();

        walker: while (try walker.next()) |child| {
            for (skiplist) |entry| {
                switch (entry) {
                    .starts_with => |name| if (std.mem.startsWith(u8, child.path, name)) continue :walker,
                    .ends_with => |name| if (std.mem.endsWith(u8, child.path, name)) continue :walker,
                }
            }

            if (std.mem.endsWith(u8, child.basename, ".h")) {
                const full = b.pathJoin(&.{ base, child.path });
                self.installHeader(upstream.path(full), child.path);
            }
        }
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
const libcrypto_nonasm = [_][]const u8{
    "aes/aes_core.c",
};

const libcrypto_include_paths = [_][]const u8{
    libcrypto_src_prefix,
    libcrypto_src_prefix ++ "asn1",
    libcrypto_src_prefix ++ "bio",
    libcrypto_src_prefix ++ "bn",
    libcrypto_src_prefix ++ "bytestring",
    libcrypto_src_prefix ++ "dh",
    libcrypto_src_prefix ++ "dsa",
    libcrypto_src_prefix ++ "curve25519",
    libcrypto_src_prefix ++ "ec",
    libcrypto_src_prefix ++ "ecdh",
    libcrypto_src_prefix ++ "ecdsa",
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

const libcrypto_macos_amd64_asm = [_][]const u8{
    "aes/aes-macosx-x86_64.S",
    "aes/bsaes-macosx-x86_64.S",
    "aes/vpaes-macosx-x86_64.S",
    "aes/aesni-macosx-x86_64.S",
    "aes/aesni-sha1-macosx-x86_64.S",
    "bn/modexp512-macosx-x86_64.S",
    "bn/mont-macosx-x86_64.S",
    "bn/mont5-macosx-x86_64.S",
    "camellia/cmll-macosx-x86_64.S",
    "md5/md5-macosx-x86_64.S",
    "modes/ghash-macosx-x86_64.S",
    "rc4/rc4-macosx-x86_64.S",
    "rc4/rc4-md5-macosx-x86_64.S",
    "sha/sha1-macosx-x86_64.S",
    "sha/sha256-macosx-x86_64.S",
    "sha/sha512-macosx-x86_64.S",
    "whrlpool/wp-macosx-x86_64.S",
    "cpuid-macosx-x86_64.S",

    "bn/arch/amd64/bignum_add.S",
    "bn/arch/amd64/bignum_cmadd.S",
    "bn/arch/amd64/bignum_cmul.S",
    "bn/arch/amd64/bignum_mul.S",
    "bn/arch/amd64/bignum_mul_4_8_alt.S",
    "bn/arch/amd64/bignum_mul_8_16_alt.S",
    "bn/arch/amd64/bignum_sqr.S",
    "bn/arch/amd64/bignum_sqr_4_8_alt.S",
    "bn/arch/amd64/bignum_sqr_8_16_alt.S",
    "bn/arch/amd64/bignum_sub.S",
    "bn/arch/amd64/word_clz.S",
    "bn/arch/amd64/bn_arch.c",
};

// these are used on armv4 with asm, or a nonasm build
const libcrypto_nonasm_or_armv4 = [_][]const u8{
    "aes/aes_cbc.c",
    "camellia/camellia.c",
    "camellia/cmll_cbc.c",
    "rc4/rc4_enc.c",
    "rc4/rc4_skey.c",
    "whrlpool/wp_block.c",
};

const libcrypto_unix_sources = [_][]const u8{
    "crypto_lock.c",
    "bio/b_posix.c",
    "bio/bss_log.c",
    "ui/ui_openssl.c",
};

const libcrypto_windows_sources = [_][]const u8{
    "compat/crypto_lock_win.c",
    "bio/b_win.c",
    "ui/ui_openssl_win.c",
    "compat/posix_win.c",
};

// TODO: trial and error these?

const libcrypto_macos_compat = [_][]const u8{
    "compat/freezero.c",
    "compat/reallocarray.c",
    "compat/recallocarray.c",

    "compat/syslog_r.c",
    "compat/explicit_bzero.c",
    "compat/timingsafe_bcmp.c",
    "compat/timingsafe_memcmp.c",
};

const libcrypto_linux_compat = [_][]const u8{
    "compat/freezero.c",
    "compat/getprogname_linux.c",

    "compat/reallocarray.c",
    "compat/recallocarray.c",

    "compat/strtonum.c",
    "compat/syslog_r.c",

    "compat/arc4random.c",
    "compat/arc4random_uniform.c",

    "compat/explicit_bzero.c",
    "compat/timingsafe_bcmp.c",
    "compat/timingsafe_memcmp.c",
};

const libcrypto_linux_musl_compat = [_][]const u8{};

const libcrypto_linux_glibc_compat = [_][]const u8{
    "compat/strlcat.c",
    "compat/strlcpy.c",

    "compat/getentropy_linux.c",
};

const libcrypto_windows_compat = [_][]const u8{
    "compat/freezero.c",
    "compat/getprogname_windows.c",
    "compat/getpagesize.c",

    "compat/reallocarray.c",
    "compat/recallocarray.c",

    "compat/strlcat.c",
    "compat/strlcpy.c",
    "compat/strndup.c",
    "compat/strsep.c",
    "compat/strtonum.c",

    "compat/syslog_r.c",
    "compat/timegm.c",

    "compat/explicit_bzero_win.c",
    "compat/getentropy_win.c",

    "compat/arc4random.c",
    "compat/arc4random_uniform.c",

    "compat/timingsafe_bcmp.c",
    "compat/timingsafe_memcmp.c",
};

const libcrypto_sources = [_][]const u8{
    "cpt_err.c",
    "cryptlib.c",
    "crypto_init.c",
    "cversion.c",
    "ex_data.c",
    "malloc-wrapper.c",
    "mem_clr.c",
    "mem_dbg.c",
    "o_fips.c",
    "o_init.c",
    "o_str.c",
    "aes/aes_cfb.c",
    "aes/aes_ctr.c",
    "aes/aes_ecb.c",
    "aes/aes_ige.c",
    "aes/aes_ofb.c",
    "aes/aes_wrap.c",
    "asn1/a_bitstr.c",
    "asn1/a_enum.c",
    "asn1/a_int.c",
    "asn1/a_mbstr.c",
    "asn1/a_object.c",
    "asn1/a_octet.c",
    "asn1/a_pkey.c",
    "asn1/a_print.c",
    "asn1/a_pubkey.c",
    "asn1/a_strex.c",
    "asn1/a_string.c",
    "asn1/a_strnid.c",
    "asn1/a_time.c",
    "asn1/a_time_posix.c",
    "asn1/a_time_tm.c",
    "asn1/a_type.c",
    "asn1/a_utf8.c",
    "asn1/asn1_err.c",
    "asn1/asn1_gen.c",
    "asn1/asn1_item.c",
    "asn1/asn1_lib.c",
    "asn1/asn1_old.c",
    "asn1/asn1_old_lib.c",
    "asn1/asn1_par.c",
    "asn1/asn1_types.c",
    "asn1/asn_mime.c",
    "asn1/asn_moid.c",
    "asn1/bio_asn1.c",
    "asn1/bio_ndef.c",
    "asn1/p5_pbe.c",
    "asn1/p5_pbev2.c",
    "asn1/p8_pkey.c",
    "asn1/t_crl.c",
    "asn1/t_req.c",
    "asn1/t_spki.c",
    "asn1/t_x509.c",
    "asn1/t_x509a.c",
    "asn1/tasn_dec.c",
    "asn1/tasn_enc.c",
    "asn1/tasn_fre.c",
    "asn1/tasn_new.c",
    "asn1/tasn_prn.c",
    "asn1/tasn_typ.c",
    "asn1/tasn_utl.c",
    "asn1/x_algor.c",
    "asn1/x_attrib.c",
    "asn1/x_bignum.c",
    "asn1/x_crl.c",
    "asn1/x_exten.c",
    "asn1/x_info.c",
    "asn1/x_long.c",
    "asn1/x_name.c",
    "asn1/x_pkey.c",
    "asn1/x_pubkey.c",
    "asn1/x_req.c",
    "asn1/x_sig.c",
    "asn1/x_spki.c",
    "asn1/x_val.c",
    "asn1/x_x509.c",
    "asn1/x_x509a.c",
    "bf/bf_cfb64.c",
    "bf/bf_ecb.c",
    "bf/bf_enc.c",
    "bf/bf_ofb64.c",
    "bf/bf_skey.c",
    "bio/b_dump.c",
    "bio/b_print.c",
    "bio/b_sock.c",
    "bio/bf_buff.c",
    "bio/bf_nbio.c",
    "bio/bf_null.c",
    "bio/bio_cb.c",
    "bio/bio_err.c",
    "bio/bio_lib.c",
    "bio/bio_meth.c",
    "bio/bss_acpt.c",
    "bio/bss_bio.c",
    "bio/bss_conn.c",
    "bio/bss_dgram.c",
    "bio/bss_fd.c",
    "bio/bss_file.c",
    "bio/bss_mem.c",
    "bio/bss_null.c",
    "bio/bss_sock.c",
    "bn/bn_add.c",
    "bn/bn_bpsw.c",
    "bn/bn_const.c",
    "bn/bn_convert.c",
    "bn/bn_ctx.c",
    "bn/bn_div.c",
    "bn/bn_err.c",
    "bn/bn_exp.c",
    "bn/bn_gcd.c",
    "bn/bn_isqrt.c",
    "bn/bn_kron.c",
    "bn/bn_lib.c",
    "bn/bn_mod.c",
    "bn/bn_mod_sqrt.c",
    "bn/bn_mont.c",
    "bn/bn_mul.c",
    "bn/bn_prime.c",
    "bn/bn_primitives.c",
    "bn/bn_print.c",
    "bn/bn_rand.c",
    "bn/bn_recp.c",
    "bn/bn_shift.c",
    "bn/bn_small_primes.c",
    "bn/bn_sqr.c",
    "bn/bn_word.c",
    "buffer/buf_err.c",
    "buffer/buffer.c",
    "bytestring/bs_ber.c",
    "bytestring/bs_cbb.c",
    "bytestring/bs_cbs.c",
    "camellia/cmll_cfb.c",
    "camellia/cmll_ctr.c",
    "camellia/cmll_ecb.c",
    "camellia/cmll_misc.c",
    "camellia/cmll_ofb.c",
    "cast/c_cfb64.c",
    "cast/c_ecb.c",
    "cast/c_enc.c",
    "cast/c_ofb64.c",
    "cast/c_skey.c",
    "chacha/chacha.c",
    "cmac/cm_ameth.c",
    "cmac/cm_pmeth.c",
    "cmac/cmac.c",
    "cms/cms_asn1.c",
    "cms/cms_att.c",
    "cms/cms_dd.c",
    "cms/cms_enc.c",
    "cms/cms_env.c",
    "cms/cms_err.c",
    "cms/cms_ess.c",
    "cms/cms_io.c",
    "cms/cms_kari.c",
    "cms/cms_lib.c",
    "cms/cms_pwri.c",
    "cms/cms_sd.c",
    "cms/cms_smime.c",
    "conf/conf_api.c",
    "conf/conf_def.c",
    "conf/conf_err.c",
    "conf/conf_lib.c",
    "conf/conf_mall.c",
    "conf/conf_mod.c",
    "conf/conf_sap.c",
    "ct/ct_b64.c",
    "ct/ct_err.c",
    "ct/ct_log.c",
    "ct/ct_oct.c",
    "ct/ct_policy.c",
    "ct/ct_prn.c",
    "ct/ct_sct.c",
    "ct/ct_sct_ctx.c",
    "ct/ct_vfy.c",
    "ct/ct_x509v3.c",
    "curve25519/curve25519-generic.c",
    "curve25519/curve25519.c",
    "des/cbc_cksm.c",
    "des/cbc_enc.c",
    "des/cfb64ede.c",
    "des/cfb64enc.c",
    "des/cfb_enc.c",
    "des/des_enc.c",
    "des/ecb3_enc.c",
    "des/ecb_enc.c",
    "des/ede_cbcm_enc.c",
    "des/enc_read.c",
    "des/enc_writ.c",
    "des/fcrypt.c",
    "des/fcrypt_b.c",
    "des/ofb64ede.c",
    "des/ofb64enc.c",
    "des/ofb_enc.c",
    "des/pcbc_enc.c",
    "des/qud_cksm.c",
    "des/set_key.c",
    "des/str2key.c",
    "des/xcbc_enc.c",
    "dh/dh_ameth.c",
    "dh/dh_asn1.c",
    "dh/dh_check.c",
    "dh/dh_err.c",
    "dh/dh_gen.c",
    "dh/dh_key.c",
    "dh/dh_lib.c",
    "dh/dh_pmeth.c",
    "dsa/dsa_ameth.c",
    "dsa/dsa_asn1.c",
    "dsa/dsa_err.c",
    "dsa/dsa_gen.c",
    "dsa/dsa_key.c",
    "dsa/dsa_lib.c",
    "dsa/dsa_meth.c",
    "dsa/dsa_ossl.c",
    "dsa/dsa_pmeth.c",
    "dsa/dsa_prn.c",
    "ec/ec_ameth.c",
    "ec/ec_asn1.c",
    "ec/ec_check.c",
    "ec/ec_curve.c",
    "ec/ec_cvt.c",
    "ec/ec_err.c",
    "ec/ec_key.c",
    "ec/ec_kmeth.c",
    "ec/ec_lib.c",
    "ec/ec_mult.c",
    "ec/ec_oct.c",
    "ec/ec_pmeth.c",
    "ec/ec_print.c",
    "ec/eck_prn.c",
    "ec/ecp_mont.c",
    "ec/ecp_oct.c",
    "ec/ecp_smpl.c",
    "ec/ecx_methods.c",
    "ecdh/ecdh.c",
    "ecdsa/ecdsa.c",
    "engine/engine_stubs.c",
    "err/err.c",
    "err/err_all.c",
    "err/err_prn.c",
    "evp/bio_b64.c",
    "evp/bio_enc.c",
    "evp/bio_md.c",
    "evp/e_aes.c",
    "evp/e_bf.c",
    "evp/e_camellia.c",
    "evp/e_cast.c",
    "evp/e_chacha.c",
    "evp/e_chacha20poly1305.c",
    "evp/e_des.c",
    "evp/e_des3.c",
    "evp/e_idea.c",
    "evp/e_null.c",
    "evp/e_rc2.c",
    "evp/e_rc4.c",
    "evp/e_sm4.c",
    "evp/e_xcbc_d.c",
    "evp/evp_aead.c",
    "evp/evp_cipher.c",
    "evp/evp_digest.c",
    "evp/evp_encode.c",
    "evp/evp_err.c",
    "evp/evp_key.c",
    "evp/evp_names.c",
    "evp/evp_pbe.c",
    "evp/evp_pkey.c",
    "evp/m_md4.c",
    "evp/m_md5.c",
    "evp/m_md5_sha1.c",
    "evp/m_null.c",
    "evp/m_ripemd.c",
    "evp/m_sha1.c",
    "evp/m_sha3.c",
    "evp/m_sigver.c",
    "evp/m_sm3.c",
    "evp/m_wp.c",
    "evp/p_legacy.c",
    "evp/p_lib.c",
    "evp/p_sign.c",
    "evp/p_verify.c",
    "evp/pmeth_fn.c",
    "evp/pmeth_gn.c",
    "evp/pmeth_lib.c",
    "hkdf/hkdf.c",
    "hmac/hm_ameth.c",
    "hmac/hm_pmeth.c",
    "hmac/hmac.c",
    "idea/i_cbc.c",
    "idea/i_cfb64.c",
    "idea/i_ecb.c",
    "idea/i_ofb64.c",
    "idea/i_skey.c",
    "kdf/hkdf_evp.c",
    "kdf/kdf_err.c",
    "lhash/lhash.c",
    "md4/md4.c",
    "md5/md5.c",
    "modes/cbc128.c",
    "modes/ccm128.c",
    "modes/cfb128.c",
    "modes/ctr128.c",
    "modes/gcm128.c",
    "modes/ofb128.c",
    "modes/xts128.c",
    "objects/obj_dat.c",
    "objects/obj_err.c",
    "objects/obj_lib.c",
    "objects/obj_xref.c",
    "ocsp/ocsp_asn.c",
    "ocsp/ocsp_cl.c",
    "ocsp/ocsp_err.c",
    "ocsp/ocsp_ext.c",
    "ocsp/ocsp_ht.c",
    "ocsp/ocsp_lib.c",
    "ocsp/ocsp_prn.c",
    "ocsp/ocsp_srv.c",
    "ocsp/ocsp_vfy.c",
    "pem/pem_all.c",
    "pem/pem_err.c",
    "pem/pem_info.c",
    "pem/pem_lib.c",
    "pem/pem_oth.c",
    "pem/pem_pk8.c",
    "pem/pem_pkey.c",
    "pem/pem_sign.c",
    "pem/pem_x509.c",
    "pem/pem_xaux.c",
    "pem/pvkfmt.c",
    "pkcs12/p12_add.c",
    "pkcs12/p12_asn.c",
    "pkcs12/p12_attr.c",
    "pkcs12/p12_crt.c",
    "pkcs12/p12_decr.c",
    "pkcs12/p12_init.c",
    "pkcs12/p12_key.c",
    "pkcs12/p12_kiss.c",
    "pkcs12/p12_mutl.c",
    "pkcs12/p12_npas.c",
    "pkcs12/p12_p8d.c",
    "pkcs12/p12_p8e.c",
    "pkcs12/p12_sbag.c",
    "pkcs12/p12_utl.c",
    "pkcs12/pk12err.c",
    "pkcs7/pk7_asn1.c",
    "pkcs7/pk7_attr.c",
    "pkcs7/pk7_doit.c",
    "pkcs7/pk7_lib.c",
    "pkcs7/pk7_mime.c",
    "pkcs7/pk7_smime.c",
    "pkcs7/pkcs7err.c",
    "poly1305/poly1305.c",
    "rand/rand_err.c",
    "rand/rand_lib.c",
    "rand/randfile.c",
    "rc2/rc2_cbc.c",
    "rc2/rc2_ecb.c",
    "rc2/rc2_skey.c",
    "rc2/rc2cfb64.c",
    "rc2/rc2ofb64.c",
    "ripemd/ripemd.c",
    "rsa/rsa_ameth.c",
    "rsa/rsa_asn1.c",
    "rsa/rsa_blinding.c",
    "rsa/rsa_chk.c",
    "rsa/rsa_eay.c",
    "rsa/rsa_err.c",
    "rsa/rsa_gen.c",
    "rsa/rsa_lib.c",
    "rsa/rsa_meth.c",
    "rsa/rsa_none.c",
    "rsa/rsa_oaep.c",
    "rsa/rsa_pk1.c",
    "rsa/rsa_pmeth.c",
    "rsa/rsa_prn.c",
    "rsa/rsa_pss.c",
    "rsa/rsa_saos.c",
    "rsa/rsa_sign.c",
    "rsa/rsa_x931.c",
    "sha/sha1.c",
    "sha/sha256.c",
    "sha/sha3.c",
    "sha/sha512.c",
    "sm3/sm3.c",
    "sm4/sm4.c",
    "stack/stack.c",
    "ts/ts_asn1.c",
    "ts/ts_conf.c",
    "ts/ts_err.c",
    "ts/ts_lib.c",
    "ts/ts_req_print.c",
    "ts/ts_req_utils.c",
    "ts/ts_rsp_print.c",
    "ts/ts_rsp_sign.c",
    "ts/ts_rsp_utils.c",
    "ts/ts_rsp_verify.c",
    "ts/ts_verify_ctx.c",
    "txt_db/txt_db.c",
    "ui/ui_err.c",
    "ui/ui_lib.c",
    "ui/ui_null.c",
    "ui/ui_util.c",
    "whrlpool/wp_dgst.c",
    "x509/by_dir.c",
    "x509/by_file.c",
    "x509/by_mem.c",
    "x509/x509_addr.c",
    "x509/x509_akey.c",
    "x509/x509_akeya.c",
    "x509/x509_alt.c",
    "x509/x509_asid.c",
    "x509/x509_att.c",
    "x509/x509_bcons.c",
    "x509/x509_bitst.c",
    "x509/x509_cmp.c",
    "x509/x509_conf.c",
    "x509/x509_constraints.c",
    "x509/x509_cpols.c",
    "x509/x509_crld.c",
    "x509/x509_d2.c",
    "x509/x509_def.c",
    "x509/x509_err.c",
    "x509/x509_ext.c",
    "x509/x509_extku.c",
    "x509/x509_genn.c",
    "x509/x509_ia5.c",
    "x509/x509_info.c",
    "x509/x509_int.c",
    "x509/x509_issuer_cache.c",
    "x509/x509_lib.c",
    "x509/x509_lu.c",
    "x509/x509_ncons.c",
    "x509/x509_obj.c",
    "x509/x509_ocsp.c",
    "x509/x509_pcons.c",
    "x509/x509_pku.c",
    "x509/x509_pmaps.c",
    "x509/x509_policy.c",
    "x509/x509_prn.c",
    "x509/x509_purp.c",
    "x509/x509_r2x.c",
    "x509/x509_req.c",
    "x509/x509_set.c",
    "x509/x509_skey.c",
    "x509/x509_trs.c",
    "x509/x509_txt.c",
    "x509/x509_utl.c",
    "x509/x509_v3.c",
    "x509/x509_verify.c",
    "x509/x509_vfy.c",
    "x509/x509_vpm.c",
    "x509/x509cset.c",
    "x509/x509name.c",
    "x509/x509rset.c",
    "x509/x509spki.c",
    "x509/x509type.c",
    "x509/x_all.c",
};

const libssl_include_paths = [_][]const u8{
    libssl_src_prefix,
    libssl_src_prefix ++ "hidden",

    libcrypto_src_prefix ++ "bio",

    // these are order-dependent and they have to go after the "hidden" directory
    // because the "openssl" include directory is masked inside the "hidden" directory
    // in the source tree. cool.
    source_header_prefix ++ "compat",
    source_header_prefix,
};

const libssl_sources = [_][]const u8{
    // these are compiled separately by Cmake, with a slightly different include path.
    // It appears they're only linked if shared libraries are being built? I don't get
    // it. I doubt always building them causes a problem, though.
    "bs_ber.c",
    "bs_cbb.c",
    "bs_cbs.c",
    // SSL_SRC
    "bio_ssl.c",
    "d1_both.c",
    "d1_lib.c",
    "d1_pkt.c",
    "d1_srtp.c",
    "pqueue.c",
    "s3_cbc.c",
    "s3_lib.c",
    "ssl_asn1.c",
    "ssl_both.c",
    "ssl_cert.c",
    "ssl_ciph.c",
    "ssl_ciphers.c",
    "ssl_clnt.c",
    "ssl_err.c",
    "ssl_init.c",
    "ssl_kex.c",
    "ssl_lib.c",
    "ssl_methods.c",
    "ssl_packet.c",
    "ssl_pkt.c",
    "ssl_rsa.c",
    "ssl_seclevel.c",
    "ssl_sess.c",
    "ssl_sigalgs.c",
    "ssl_srvr.c",
    "ssl_stat.c",
    "ssl_tlsext.c",
    "ssl_transcript.c",
    "ssl_txt.c",
    "ssl_versions.c",
    "t1_enc.c",
    "t1_lib.c",
    "tls_buffer.c",
    "tls_content.c",
    "tls_key_share.c",
    "tls_lib.c",
    "tls12_key_schedule.c",
    "tls12_lib.c",
    "tls12_record_layer.c",
    "tls13_client.c",
    "tls13_error.c",
    "tls13_handshake.c",
    "tls13_handshake_msg.c",
    "tls13_key_schedule.c",
    "tls13_legacy.c",
    "tls13_lib.c",
    "tls13_quic.c",
    "tls13_record.c",
    "tls13_record_layer.c",
    "tls13_server.c",
};

const libtls_include_paths = [_][]const u8{
    libssl_src_prefix,
    source_header_prefix ++ "compat",
    source_header_prefix,
};

const libtls_sources = [_][]const u8{
    "tls.c",
    "tls_bio_cb.c",
    "tls_client.c",
    "tls_config.c",
    "tls_conninfo.c",
    "tls_keypair.c",
    "tls_server.c",
    "tls_signer.c",
    "tls_ocsp.c",
    "tls_peer.c",
    "tls_util.c",
    "tls_verify.c",
};

const libtls_windows_sources = [_][]const u8{
    "compat/ftruncate.c",
    "compat/pread.c",
    "compat/pwrite.c",
};
