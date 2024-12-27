# LibreSSL

This is [LibreSSL Portable](https://github.com/libressl/portable), packaged for [Zig](https://ziglang.org/).

## Status

This project currently builds the three main LibreSSL libraries as static libraries:

- `libcrypto`: core cryptographic routines
- `libssl`: OpenSSL 1.1 compatibility layer
- `libtls`: LibreSSL's new cryptography API

Operating systems and hardware architectures are supported on a best-effort basis, and patches to add additional OS/arch support are welcome. Building for Linux (`x86_64`), macOS (`aarch64`), and Windows (`x86_64` via `mingw64`) is directly tested by CI.

The command-line programs `nc`, `ocspcheck`, and `openssl` are not built by default, and building them when targeting Windows is not supported. Building the command-line programs may be enabled by specifing the `-Dbuild-apps` option to `zig build`

## Usage

First, update your `build.zig.zon`:

```sh
# Initialize a `zig build` project if you haven't already
zig init
# replace <refname> with the version you want to use, e.g. 4.0.0
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

## Zig Version Support Matrix

| Refname   | LibreSSL Version | Zig `0.12.x` | Zig `0.13.x` | Zig `0.14.0-dev` |
|-----------|------------------|--------------|--------------|------------------|
| `3.9.2+1` | `3.9.2`          | ✅           | ✅           | ✅               |
| `4.0.0+1` | `4.0.0`          | ✅           | ✅           | ✅               |
