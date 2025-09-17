+const std = @import("std");
+
+pub fn build(b: *std.Build) void {
+    const target = b.standardTargetOptions(.{});
+    const optimize = b.standardOptimizeOption(.{});
+
+    const tardy = b.dependency("tardy", .{
+        .target = target,
+        .optimize = optimize,
+    }).module("tardy");
+
+    const bearssl = b.dependency("bearssl", .{
+        .target = target,
+        .optimize = optimize,
+        .BR_LE_UNALIGNED = false,
+        .BR_BE_UNALIGNED = false,
+        // Enable OS-backed RNG and time in BearSSL so we don't
+        // have to manually seed/inject time for X.509.
+        .BR_USE_RANDOM = true,
+        .BR_USE_UNIX_TIME = true,
+    }).artifact("bearssl");
+
+    const lib = b.addModule("secsock", .{
+        .root_source_file = b.path("src/lib.zig"),
+        .target = target,
+        .optimize = optimize,
+    });
+
+    lib.linkLibrary(bearssl);
+    lib.addImport("tardy", tardy);
+
+    // add_example(b, "s2n", target, optimize, tardy, lib);
+    add_example(b, "bearssl", target, optimize, tardy, lib);
+    add_example(b, "bearssl_client", target, optimize, tardy, lib);
+}
+
+fn add_example(
+    b: *std.Build,
+    name: []const u8,
+    target: std.Build.ResolvedTarget,
+    optimize: std.builtin.OptimizeMode,
+    tardy_module: *std.Build.Module,
+    secsock_module: *std.Build.Module,
+) void {
+    const exe_mod = b.createModule(.{
+        .root_source_file = b.path(b.fmt("examples/{s}/main.zig", .{name})),
+        .target = target,
+        .optimize = optimize,
+    });
+    const example = b.addExecutable(.{ .name = b.fmt("{s}", .{name}), .root_module = exe_mod });
+
+    if (target.result.os.tag == .windows) {
+        example.linkLibC();
+    }
+
+    exe_mod.addImport("tardy", tardy_module);
+    exe_mod.addImport("secsock", secsock_module);
+    const install_artifact = b.addInstallArtifact(example, .{});
+    b.getInstallStep().dependOn(&install_artifact.step);
+
+    const build_step = b.step(b.fmt("{s}", .{name}), b.fmt("Build tardy example ({s})", .{name}));
+    build_step.dependOn(&install_artifact.step);
+
+    const run_artifact = b.addRunArtifact(example);
+    run_artifact.step.dependOn(&install_artifact.step);
+
+    const run_step = b.step(b.fmt("run_{s}", .{name}), b.fmt("Run tardy example ({s})", .{name}));
+    run_step.dependOn(&install_artifact.step);
+    run_step.dependOn(&run_artifact.step);
+}
