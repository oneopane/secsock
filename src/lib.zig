//! Secure Sockets - TLS functionality for Tardy Sockets

const std = @import("std");

const tardy = @import("tardy");
const Runtime = tardy.Runtime;
const Socket = tardy.Socket;

pub const s2n = @import("s2n.zig").s2n;

pub const SecureSocket = struct {
    const VTable = struct {
        inner: *anyopaque,

        deinit: *const fn (*anyopaque) void,

        accept: *const fn (Socket, *Runtime, *anyopaque) anyerror!SecureSocket,
        connect: *const fn (Socket, *Runtime, *anyopaque) anyerror!void,

        recv: *const fn (*Runtime, *anyopaque, []u8) anyerror!usize,
        send: *const fn (*Runtime, *anyopaque, []const u8) anyerror!usize,
    };

    socket: Socket,
    vtable: VTable,

    pub fn deinit(self: *const SecureSocket) void {
        return self.vtable.deinit(self.vtable.inner);
    }

    pub fn accept(self: *const SecureSocket, rt: *Runtime) !SecureSocket {
        return try self.vtable.accept(self.socket, rt, self.vtable.inner);
    }

    pub fn connect(self: *const SecureSocket, rt: *Runtime) !void {
        return try self.vtable.connect(self.socket, rt, self.vtable.inner);
    }

    pub fn recv(self: *const SecureSocket, rt: *Runtime, buffer: []u8) !usize {
        return try self.vtable.recv(rt, self.vtable.inner, buffer);
    }

    pub fn send(self: *const SecureSocket, rt: *Runtime, buffer: []const u8) !usize {
        return try self.vtable.send(rt, self.vtable.inner, buffer);
    }
};
