# LibreSSL

This is [LibreSSL Portable](https://github.com/libressl/portable), packaged for [Zig](https://ziglang.org/).

## Installation

First, update your `build.zig.zon`:

```
# Initialize a `zig build` project if you haven't already
zig init
zig fetch --save <PLACEHOLDER>
```

You can then import `libressl` in your `build.zig` with:

```zig
const libressl_dependency = b.dependency("libressl", .{
    .target = target,
    .optimize = optimize,
});
your_exe.linkLibrary(libressl_dependency.artifact("tls"));
```
