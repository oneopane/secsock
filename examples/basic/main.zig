const std = @import("std");

const Tardy = @import("tardy").Tardy(.auto);
const Timer = @import("tardy").Timer;
const Socket = @import("tardy").Socket;
const Runtime = @import("tardy").Runtime;

const tls = @import("tls");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var tardy = try Tardy.init(allocator, .{ .threading = .single });
    defer tardy.deinit();

    var s2n = try tls.s2n.init(allocator);
    defer s2n.deinit();
    try s2n.add_cert_chain(@embedFile("cert.pem"), @embedFile("key.pem"));

    try tardy.entry(&s2n, struct {
        fn entry(rt: *Runtime, s: *const tls.s2n) !void {
            try rt.spawn(.{ rt, s }, echo_frame, 1024 * 1024 * 16);
        }
    }.entry);
}

fn echo_frame(rt: *Runtime, s2n: *const tls.s2n) !void {
    const socket = try Socket.init(.{ .tcp = .{ .host = "127.0.0.1", .port = 9862 } });
    defer socket.close_blocking();
    try socket.bind();
    try socket.listen(128);

    const secure = try s2n.to_secure_socket(rt, socket);
    defer secure.deinit();

    const connected = try secure.accept(rt);
    defer connected.deinit();
    defer connected.socket.close_blocking();

    while (true) {
        _ = connected.send(rt, "abcdef\n") catch |e| switch (e) {
            error.Closed => break,
            else => return e,
        };
        try Timer.delay(rt, .{ .seconds = 1 });
    }
}
