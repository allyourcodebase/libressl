# LibreSSL

This is [LibreSSL Portable](https://github.com/libressl/portable), packaged for [Zig](https://ziglang.org/).

## Status

This project currently builds the three main LibreSSL libraries as static libraries:

- `libcrypto`: core cryptographic routines
- `libssl`: OpenSSL 1.1 compatibility layer
- `libtls`: LibreSSL's new cryptography API

Operating systems and hardware architectures are supported on a best-effort basis. Building for Linux, macOS, and Windows (mingw64) is directly tested by CI.

The command line programs `nc`, `ocspcheck`, and `openssl` are **not** currently built by this build system.

## Usage

First, update your `build.zig.zon`:

```sh
# Initialize a `zig build` project if you haven't already
zig init
# replace <refname> with the version you want to use, e.g. 3.9.2
zig fetch --save git+https://github.com/allyourcodebase/libressl#<refname>
```

You can then use `libressl` in your `build.zig` as follows:

```zig
const libressl_dependency = b.dependency("libressl", .{
    .target = target,
    .optimize = optimize,
    .@"enable-asm" = true, // enable assembly routines on supported platforms
});
your_exe.linkLibrary(libressl_dependency.artifact("tls")); // or "ssl", or "crypto"
```

## Version Support Matrix

|  Refname | LibreSSL Version | Zig `0.12.x` | Zig `0.13.x` | Zig `0.14.0-dev` |
|----------|------------------|--------------|--------------|------------------|
| `3.9.2`  | `3.9.2`          | ✅           | ✅          | ✅              |
