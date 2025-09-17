const std = @import("std");

const Tardy = @import("tardy").Tardy(.auto);
const Runtime = @import("tardy").Runtime;
const Socket = @import("tardy").Socket;

const secsock = @import("secsock");
const SecureSocket = secsock.SecureSocket;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var tardy = try Tardy.init(allocator, .{ .threading = .single });
    defer tardy.deinit();

    var bearssl = secsock.BearSSL.init(allocator);
    defer bearssl.deinit();

    // Trust the server's test certificate (direct trust)
    try bearssl.add_trust_anchor_pem(
        "CERTIFICATE",
        @embedFile("certs/rsa_cert.pem"),
    );

    // Connect to the example server running on 127.0.0.1:9862
    const socket = try Socket.init(.{ .tcp = .{ .host = "127.0.0.1", .port = 9862 } });
    defer socket.close_blocking();

    const secure = try bearssl.to_secure_socket(socket, .client);
    defer secure.deinit();

    try tardy.entry(&secure, struct {
        fn entry(rt: *Runtime, s: *const SecureSocket) !void {
            try rt.spawn(.{ rt, s }, client_task, 1024 * 1024);
        }
    }.entry);
}

fn client_task(rt: *Runtime, s: *const SecureSocket) !void {
    try s.connect(rt);

    const msg = "hello over tls";
    _ = try s.send_all(rt, msg);

    var buf: [256]u8 = undefined;
    const n = try s.recv(rt, &buf);
    std.log.info("client got: {s}", .{buf[0..n]});
}
