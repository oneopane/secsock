const std = @import("std");

const tardy = @import("tardy");
const Socket = tardy.Socket;
const Runtime = tardy.Runtime;

const SecureSocket = @import("../lib.zig").SecureSocket;
const BearSSL = @import("lib.zig").BearSSL;
const PrivateKey = BearSSL.PrivateKey;
const EngineStatus = @import("lib.zig").EngineStatus;

const log = std.log.scoped(.@"bearssl/client");

const c = @cImport({
    @cInclude("bearssl.h");
});

pub fn to_secure_socket_client(self: *BearSSL, socket: Socket) !SecureSocket {
    const CallbackContext = struct { socket: Socket, runtime: ?*Runtime };
    const VtableContext = struct {
        allocator: std.mem.Allocator,
        bearssl: *BearSSL,
        io_buf: []const u8,
        sslio_ctx: c.br_sslio_context,
        cb_ctx: *CallbackContext,
        context: c.br_ssl_client_context,
        x509_ctx: c.br_x509_minimal_context,
    };

    const io_buf = try self.allocator.alloc(u8, c.BR_SSL_BUFSIZE_BIDI);
    errdefer self.allocator.free(io_buf);

    const cb_ctx = try self.allocator.create(CallbackContext);
    errdefer self.allocator.destroy(cb_ctx);
    cb_ctx.* = .{ .runtime = null, .socket = socket };

    const ctx = try self.allocator.create(VtableContext);
    errdefer self.allocator.destroy(ctx);
    ctx.* = .{
        .allocator = self.allocator,
        .bearssl = self,
        .context = undefined,
        .x509_ctx = undefined,
        .io_buf = io_buf,
        .cb_ctx = cb_ctx,
        .sslio_ctx = undefined,
    };

    // Initialize client context with X.509 minimal validation using provided trust anchors.
    var anchors_ptr: ?[*c]const c.br_x509_trust_anchor = null;
    if (self.trust_anchors.items.len != 0) {
        anchors_ptr = @ptrCast(self.trust_anchors.items.ptr);
    }
    c.br_ssl_client_init_full(
        &ctx.context,
        &ctx.x509_ctx,
        anchors_ptr orelse @ptrFromInt(0),
        self.trust_anchors.items.len,
    );

    // Optional: attach client certificate for mutual TLS if configured
    if (self.x509 != null and self.pkey != null) switch (self.pkey.?) {
        .rsa => |*key| blk: {
            const chain_ptr: [*c]const c.br_x509_certificate = @ptrCast(&self.x509.?);
            const sk_ptr: [*c]const c.br_rsa_private_key = @ptrCast(key);
            break :blk c.br_ssl_client_set_single_rsa(
                &ctx.context,
                chain_ptr,
                1,
                sk_ptr,
                c.br_rsa_pkcs1_sign_get_default(),
            );
        },
        .ec => |*key| blk: {
            const chain_ptr: [*c]const c.br_x509_certificate = @ptrCast(&self.x509.?);
            const sk_ptr: [*c]const c.br_ec_private_key = @ptrCast(key);
            break :blk c.br_ssl_client_set_single_ec(
                &ctx.context,
                chain_ptr,
                1,
                sk_ptr,
                c.BR_KEYTYPE_KEYX | c.BR_KEYTYPE_SIGN,
                @intCast(self.cert_signer_algo orelse c.BR_KEYTYPE_EC),
                c.br_ec_get_default(),
                c.br_ecdsa_sign_asn1_get_default(),
            );
        },
    };

    // Single shared buffer, full-duplex mode
    c.br_ssl_engine_set_buffer(&ctx.context.eng, io_buf.ptr, io_buf.len, 1);

    // Set SNI / name matching (copied internally by BearSSL)
    var sni_z: ?[:0]const u8 = null;
    if (self.sni_server_name) |sni| {
        sni_z = try self.allocator.dupeZ(u8, sni);
    }
    defer if (sni_z) |z| self.allocator.free(z);

    const reset_status = c.br_ssl_client_reset(&ctx.context, if (sni_z) |z| @ptrCast(z.ptr) else null, 0);
    if (reset_status <= 0) return error.ClientResetFailed;

    // Wrap in the simplified I/O interface for post-handshake read/write
    c.br_sslio_init(
        &ctx.sslio_ctx,
        &ctx.context.eng,
        struct {
            fn recv_cb(i: ?*anyopaque, b: [*c]u8, l: usize) callconv(.c) c_int {
                const cb: *CallbackContext = @ptrCast(@alignCast(i.?));
                const len = cb.socket.recv(cb.runtime.?, b[0..l]) catch |e| {
                    log.err("sslio recv cb failed: {s}", .{@errorName(e)});
                    return -1;
                };
                return @intCast(len);
            }
        }.recv_cb,
        cb_ctx,
        struct {
            fn send_cb(i: ?*anyopaque, b: [*c]const u8, l: usize) callconv(.c) c_int {
                const cb: *CallbackContext = @ptrCast(@alignCast(i.?));
                const len = cb.socket.send(cb.runtime.?, b[0..l]) catch |e| {
                    log.err("sslio send cb failed: {s}", .{@errorName(e)});
                    return -1;
                };
                return @intCast(len);
            }
        }.send_cb,
        cb_ctx,
    );

    return SecureSocket{
        .socket = socket,
        .vtable = .{
            .inner = ctx,
            .deinit = struct {
                fn deinit(i: *anyopaque) void {
                    const v: *VtableContext = @ptrCast(@alignCast(i));
                    v.allocator.destroy(v.cb_ctx);
                    v.allocator.free(v.io_buf);
                    v.allocator.destroy(v);
                }
            }.deinit,
            .accept = struct {
                fn accept(_: Socket, _: *Runtime, _: *anyopaque) !SecureSocket {
                    return error.TLSClientCantAccept;
                }
            }.accept,
            .connect = struct {
                fn connect(s: Socket, r: *Runtime, i: *anyopaque) !void {
                    const v: *VtableContext = @ptrCast(@alignCast(i));
                    v.cb_ctx.runtime = r;

                    try s.connect(r);

                    // Drive the handshake to completion using the engine-level API.
                    while (true) {
                        const st: c_uint = c.br_ssl_engine_current_state(&v.context.eng);

                        if ((st & (c.BR_SSL_SENDAPP | c.BR_SSL_RECVAPP)) != 0) {
                            break; // handshake finished
                        }

                        if ((st & c.BR_SSL_SENDREC) != 0) {
                            var out_len: usize = 0;
                            const out_ptr = c.br_ssl_engine_sendrec_buf(&v.context.eng, &out_len);
                            if (out_len == 0 or out_ptr == null) {
                                // nothing to send right now
                            } else {
                                var sent_total: usize = 0;
                                const out_slice = out_ptr[0..out_len];
                                while (sent_total < out_len) {
                                    const wrote = v.cb_ctx.socket.send(v.cb_ctx.runtime.?, out_slice[sent_total..]) catch |e| switch (e) {
                                        error.Closed => return error.Closed,
                                        else => {
                                            log.err("handshake send failed: {s}", .{@errorName(e)});
                                            return error.TlsSendFailed;
                                        },
                                    };
                                    if (wrote == 0) return error.TlsSendFailed;
                                    c.br_ssl_engine_sendrec_ack(&v.context.eng, wrote);
                                    sent_total += wrote;
                                }
                                continue;
                            }
                        }

                        if ((st & c.BR_SSL_RECVREC) != 0) {
                            var in_len: usize = 0;
                            const in_ptr = c.br_ssl_engine_recvrec_buf(&v.context.eng, &in_len);
                            if (in_len == 0 or in_ptr == null) {
                                // nothing expected right now
                            } else {
                                const got = v.cb_ctx.socket.recv(v.cb_ctx.runtime.?, in_ptr[0..in_len]) catch |e| switch (e) {
                                    error.Closed => return error.Closed,
                                    else => {
                                        log.err("handshake recv failed: {s}", .{@errorName(e)});
                                        return error.TlsRecvFailed;
                                    },
                                };
                                if (got == 0) return error.Closed;
                                c.br_ssl_engine_recvrec_ack(&v.context.eng, got);
                                continue;
                            }
                        }

                        if ((st & c.BR_SSL_CLOSED) != 0) {
                            const last = EngineStatus.convert(c.br_ssl_engine_last_error(&v.context.eng));
                            switch (last) {
                                .InputOutput => return error.Closed,
                                else => {
                                    log.err("handshake closed with status: {s}", .{@tagName(last)});
                                    return error.TlsHandshakeFailed;
                                },
                            }
                        }
                    }
                }
            }.connect,
            .recv = struct {
                fn recv(_: Socket, r: *Runtime, i: *anyopaque, b: []u8) !usize {
                    const v: *VtableContext = @ptrCast(@alignCast(i));
                    v.cb_ctx.runtime = r;

                    const result = c.br_sslio_read(&v.sslio_ctx, b.ptr, b.len);
                    if (result < 0) {
                        const last = EngineStatus.convert(c.br_ssl_engine_last_error(&v.context.eng));
                        switch (last) {
                            .InputOutput => return error.Closed,
                            else => {
                                log.err("sslio recv failed: {s}", .{@tagName(last)});
                                return error.TlsRecvFailed;
                            },
                        }
                    }
                    return @intCast(result);
                }
            }.recv,
            .send = struct {
                fn send(_: Socket, r: *Runtime, i: *anyopaque, b: []const u8) !usize {
                    const v: *VtableContext = @ptrCast(@alignCast(i));
                    v.cb_ctx.runtime = r;

                    const write_result = c.br_sslio_write(&v.sslio_ctx, b.ptr, b.len);
                    if (write_result < 0) {
                        const last_error = EngineStatus.convert(c.br_ssl_engine_last_error(&v.context.eng));
                        switch (last_error) {
                            .InputOutput => return error.Closed,
                            else => {
                                log.err("sslio send failed: {s}", .{@tagName(last_error)});
                                return error.TlsSendFailed;
                            },
                        }
                    }

                    const flush_result = c.br_sslio_flush(&v.sslio_ctx);
                    if (flush_result < 0) {
                        const last_error = EngineStatus.convert(c.br_ssl_engine_last_error(&v.context.eng));
                        switch (last_error) {
                            .InputOutput => return error.Closed,
                            else => {
                                log.err("sslio flush failed: {s}", .{@tagName(last_error)});
                                return error.TlsSendFailed;
                            },
                        }
                    }

                    return @intCast(write_result);
                }
            }.send,
        },
    };
}
