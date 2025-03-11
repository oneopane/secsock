const std = @import("std");
const assert = std.debug.assert;

const tardy = @import("tardy");
const Socket = tardy.Socket;
const Runtime = tardy.Runtime;

const SecureSocket = @import("../lib.zig").SecureSocket;
const BearSSL = @import("lib.zig").BearSSL;
const PrivateKey = BearSSL.PrivateKey;
const EngineStatus = @import("lib.zig").EngineStatus;

const log = std.log.scoped(.@"bearssl/server");

const c = @cImport({
    @cInclude("bearssl.h");
});

const PolicyContext = struct {
    vtable: *const c.br_ssl_server_policy_class,
    chain: *const c.br_x509_certificate,
    pkey: PrivateKey,
    cert_signer_algo: c_int,
};

fn get_hash_oid(id: c_uint) ![:0]const u8 {
    const hash_oids = [_][:0]const u8{
        // SHA1
        &.{ 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A },
        // SHA224
        &.{ 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 },
        // SHA256
        &.{ 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 },
        // SHA384
        &.{ 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 },
        // SHA512
        &.{ 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 },
    };

    return if (id >= 2 and id <= 6)
        hash_oids[@intCast(id - 2)]
    else
        error.InvalidHashId;
}

const HashFunction = struct {
    name: []const u8,
    hclass: *const c.br_hash_class,
    comment: []const u8,
};

fn choose_hash(hashes: u32) u32 {
    var hash_id: u32 = 6;

    while (hash_id >= 2) : (hash_id -= 1) if (((hashes >> @intCast(hash_id)) & 0x1) != 0)
        return @intCast(hash_id);

    unreachable;
}

fn get_hash_impl(hash_id: c_uint) !*const c.br_hash_class {
    const hash_functions = [_]HashFunction{
        HashFunction{ .name = "md5", .hclass = &c.br_md5_vtable, .comment = "MD5" },
        HashFunction{ .name = "sha1", .hclass = &c.br_sha1_vtable, .comment = "SHA-1" },
        HashFunction{ .name = "sha224", .hclass = &c.br_sha224_vtable, .comment = "SHA-224" },
        HashFunction{ .name = "sha256", .hclass = &c.br_sha256_vtable, .comment = "SHA-256" },
        HashFunction{ .name = "sha384", .hclass = &c.br_sha384_vtable, .comment = "SHA-384" },
        HashFunction{ .name = "sha512", .hclass = &c.br_sha512_vtable, .comment = "SHA-512" },
    };

    for (hash_functions) |hash| {
        const id = (hash.hclass.desc >> c.BR_HASHDESC_ID_OFF) & c.BR_HASHDESC_ID_MASK;
        if (id == hash_id) return hash.hclass;
    }

    return error.HashNotSupported;
}

fn choose(
    pctx: [*c][*c]const c.br_ssl_server_policy_class,
    ctx: [*c]const c.br_ssl_server_context,
    choices: [*c]c.br_ssl_server_choices,
) callconv(.c) c_int {
    // https://www.bearssl.org/apidoc/structbr__ssl__server__policy__class__.html
    const policy: *const PolicyContext = @ptrCast(@alignCast(pctx));

    var suite_num: usize = 0;
    const suites: [*c]const c.br_suite_translated = c.br_ssl_server_get_client_suites(ctx, &suite_num);
    const hashes: u32 = c.br_ssl_server_get_client_hashes(ctx);

    switch (ctx.*.client_max_version) {
        c.BR_SSL30, c.BR_TLS10, c.BR_TLS11 => return 0,
        c.BR_TLS12 => {},
        else => return 0,
    }

    choices.*.chain = policy.chain;
    choices.*.chain_len = 1;

    for (0..suite_num) |i| {
        const tt = suites[i][1];

        switch (tt >> 12) {
            // BORKED
            c.BR_SSLKEYX_RSA => switch (policy.pkey) {
                .rsa => {
                    log.debug("Choosing BR_SSLKEYX_RSA", .{});
                    choices.*.cipher_suite = suites[i][0];
                    return 1;
                },
                else => continue,
            },
            // BORKED
            c.BR_SSLKEYX_ECDHE_RSA => switch (policy.pkey) {
                .rsa => {
                    log.debug("Choosing BR_SSLKEYX_ECDHE_RSA", .{});
                    choices.*.cipher_suite = suites[i][0];

                    if (c.br_ssl_engine_get_version(&ctx.*.eng) < c.BR_TLS12) {
                        choices.*.algo_id = 0xFF00;
                    } else {
                        const id = choose_hash(hashes);
                        choices.*.algo_id = 0xFF00 + id;
                    }

                    return 1;
                },
                else => continue,
            },
            c.BR_SSLKEYX_ECDHE_ECDSA => switch (policy.pkey) {
                .ec => {
                    log.debug("Choosing BR_SSLKEYX_ECDHE_ECDSA", .{});
                    choices.*.cipher_suite = suites[i][0];

                    if (c.br_ssl_engine_get_version(&ctx.*.eng) < c.BR_TLS12) {
                        choices.*.algo_id = 0xFF00 + c.br_sha1_ID;
                    } else {
                        const id = choose_hash(hashes >> 8);
                        choices.*.algo_id = 0xFF00 + id;
                    }

                    return 1;
                },
                else => continue,
            },
            // BORKED
            c.BR_SSLKEYX_ECDH_RSA => switch (policy.pkey) {
                .ec => if (policy.cert_signer_algo == c.BR_KEYTYPE_RSA) {
                    log.debug("Choosing BR_SSLKEYX_ECDH_RSA", .{});
                    choices.*.cipher_suite = suites[i][0];
                    return 1;
                } else continue,
                else => continue,
            },
            c.BR_SSLKEYX_ECDH_ECDSA => switch (policy.pkey) {
                .ec => if (policy.cert_signer_algo == c.BR_KEYTYPE_EC) {
                    log.debug("Choosing BR_SSLKEYX_ECDH_ECDSA", .{});
                    choices.*.cipher_suite = suites[i][0];
                    return 1;
                } else continue,
                else => continue,
            },
            else => {
                log.warn("unknown client suite: {d}", .{tt >> 12});
                return 0;
            },
        }
    }

    return 0;
}

fn do_keyx(
    pctx: [*c][*c]const c.br_ssl_server_policy_class,
    data: [*c]u8,
    len: [*c]usize,
) callconv(.c) u32 {
    const policy: *const PolicyContext = @ptrCast(@alignCast(pctx));
    switch (policy.pkey) {
        .rsa => |*inner| return c.br_rsa_ssl_decrypt(
            c.br_rsa_private_get_default(),
            inner,
            data,
            len.*,
        ),
        .ec => |*inner| {
            const iec = c.br_ec_get_default();
            const r = iec.*.mul.?(data, len.*, inner.x, inner.xlen, inner.curve);
            var xlen: usize = 0;
            const xoff = iec.*.xoff.?(inner.curve, &xlen);
            std.mem.copyForwards(u8, data[0..len.*], data[xoff .. xoff + xlen]);
            len.* = xlen;
            return r;
        },
    }
}

fn do_sign(
    pctx: [*c][*c]const c.br_ssl_server_policy_class,
    algo_id: c_uint,
    data: [*c]u8,
    hv_len: usize,
    len: usize,
) callconv(.C) usize {
    const policy: *const PolicyContext = @ptrCast(@alignCast(pctx));

    var hv: [64]u8 = @splat(0);
    var algo_inner_id = algo_id;
    var hv_inner_len = hv_len;

    if (algo_inner_id >= 0xFF00) {
        algo_inner_id &= 0xFF;
        @memcpy(&hv, data[0..hv_inner_len]);
    } else {
        algo_inner_id >>= 8;
        const hc = get_hash_impl(algo_inner_id) catch {
            log.err("unsupported hash function: {d}", .{algo_inner_id});
            return 0;
        };

        var zc: c.br_hash_compat_context = undefined;
        hc.init.?(&zc.vtable);
        hc.update.?(&zc.vtable, data, hv_inner_len);
        hc.out.?(&zc.vtable, &hv[0]);
        hv_inner_len = (hc.desc >> c.BR_HASHDESC_OUT_OFF) & c.BR_HASHDESC_OUT_MASK;
    }

    switch (policy.pkey) {
        .rsa => |*inner| {
            const hash_oid = get_hash_oid(algo_inner_id) catch return 0;
            const sig_len: usize = (inner.n_bitlen + 7) >> 3;
            if (len < sig_len) return 0;

            const sign_fn = c.br_rsa_pkcs1_sign_get_default().?;
            const x = sign_fn(hash_oid.ptr, &hv[0], hv_inner_len, inner, data);
            if (x == 0) {
                log.err("rsa-signed failure", .{});
                return 0;
            }
            return sig_len;
        },
        .ec => |*inner| {
            var sig_len: usize = 0;
            const class = get_hash_impl(algo_inner_id) catch {
                log.err("unsupported hash function {d}", .{algo_inner_id});
                return 0;
            };

            if (len < 139) {
                log.err("failed to ecdsa-sign, wrong len={d}", .{len});
                return 0;
            }

            sig_len = c.br_ecdsa_sign_asn1_get_default().?(
                c.br_ec_get_default(),
                class,
                &hv,
                inner,
                data,
            );

            if (sig_len == 0) {
                log.err("failed to ecdsa-sign, sig_len=0", .{});
                return 0;
            }

            return sig_len;
        },
    }

    return 0;
}

const policy_vtable: c.br_ssl_server_policy_class = .{
    .context_size = @sizeOf(PolicyContext),
    .choose = choose,
    .do_keyx = do_keyx,
    .do_sign = do_sign,
};

pub fn to_secure_socket_server(self: *BearSSL, socket: Socket) !SecureSocket {
    const CallbackContext = struct { socket: Socket, runtime: ?*Runtime };
    const VtableContext = struct {
        allocator: std.mem.Allocator,
        bearssl: *BearSSL,
        io_buf: []const u8,
        sslio_ctx: c.br_sslio_context,
        cb_ctx: *CallbackContext,
        context: c.br_ssl_server_context,
        policy: PolicyContext,
    };

    var srv_ctx: c.br_ssl_server_context = undefined;

    switch (self.pkey.?) {
        .rsa => |*inner| c.br_ssl_server_init_full_rsa(
            &srv_ctx,
            &self.x509.?,
            1,
            inner,
        ),
        .ec => |*inner| {
            assert(inner.x != 0);
            assert(inner.curve != 0);
            assert(inner.xlen != 0);
            c.br_ssl_server_init_full_ec(
                &srv_ctx,
                &self.x509.?,
                1,
                @intCast(self.cert_signer_algo.?),
                inner,
            );
        },
    }

    if (c.br_ssl_engine_last_error(&srv_ctx.eng) != 0) return error.ServerInitFailed;

    const io_buf = try self.allocator.alloc(u8, c.BR_SSL_BUFSIZE_BIDI);
    errdefer self.allocator.free(io_buf);

    const cb_ctx = try self.allocator.create(CallbackContext);
    errdefer self.allocator.destroy(cb_ctx);
    cb_ctx.* = .{ .runtime = null, .socket = socket };

    const context = try self.allocator.create(VtableContext);
    errdefer self.allocator.destroy(context);
    context.* = .{
        .allocator = self.allocator,
        .bearssl = self,
        .context = srv_ctx,
        .io_buf = io_buf,
        .policy = .{
            .vtable = &policy_vtable,
            .chain = &self.x509.?,
            .pkey = self.pkey.?,
            .cert_signer_algo = self.cert_signer_algo.?,
        },
        .cb_ctx = cb_ctx,
        .sslio_ctx = undefined,
    };

    const srv = &context.context;
    const engine = &srv.eng;

    c.br_ssl_engine_set_buffer(engine, io_buf.ptr, io_buf.len, 1);
    c.br_ssl_server_set_policy(srv, @ptrCast(&context.policy.vtable));

    const reset_status = c.br_ssl_server_reset(srv);
    if (reset_status <= 0) return error.ServerResetFailed;

    c.br_sslio_init(
        &context.sslio_ctx,
        engine,
        struct {
            fn recv_cb(i: ?*anyopaque, b: [*c]u8, l: usize) callconv(.c) c_int {
                const ctx: *CallbackContext = @ptrCast(@alignCast(i.?));
                const len = ctx.socket.recv(ctx.runtime.?, b[0..l]) catch |e| {
                    log.err("sslio recv cb failed: {s}", .{@errorName(e)});
                    return -1;
                };
                return @intCast(len);
            }
        }.recv_cb,
        cb_ctx,
        struct {
            fn send_cb(i: ?*anyopaque, b: [*c]const u8, l: usize) callconv(.c) c_int {
                const ctx: *CallbackContext = @ptrCast(@alignCast(i.?));
                const len = ctx.socket.send(ctx.runtime.?, b[0..l]) catch |e| {
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
            .inner = context,
            .deinit = struct {
                fn deinit(i: *anyopaque) void {
                    const ctx: *VtableContext = @ptrCast(@alignCast(i));

                    ctx.allocator.destroy(ctx.cb_ctx);
                    ctx.allocator.free(ctx.io_buf);
                    ctx.allocator.destroy(ctx);
                }
            }.deinit,
            .accept = struct {
                fn accept(s: Socket, r: *Runtime, i: *anyopaque) !SecureSocket {
                    const ctx: *VtableContext = @ptrCast(@alignCast(i));
                    const sock = try s.accept(r);
                    errdefer sock.close_blocking();

                    const child = try ctx.bearssl.to_secure_socket(sock, .server);
                    // if we fail, we want to clean this connection up.
                    errdefer child.deinit();
                    const new_ctx: *VtableContext = @ptrCast(@alignCast(child.vtable.inner));
                    new_ctx.cb_ctx.runtime = r;

                    return child;
                }
            }.accept,
            .connect = struct {
                fn connect(_: Socket, _: *Runtime, _: *anyopaque) !void {
                    return error.TLSServerCantConnect;
                }
            }.connect,
            .recv = struct {
                fn recv(_: Socket, r: *Runtime, i: *anyopaque, b: []u8) !usize {
                    const ctx: *VtableContext = @ptrCast(@alignCast(i));
                    ctx.cb_ctx.runtime = r;

                    const result = c.br_sslio_read(&ctx.sslio_ctx, b.ptr, b.len);
                    if (result < 0) {
                        const last_error = EngineStatus.convert(c.br_ssl_engine_last_error(&ctx.context.eng));
                        switch (last_error) {
                            .Ok, .InputOutput => return error.Closed,
                            else => {
                                log.err("sslio recv failed: {s}", .{@tagName(last_error)});
                                return error.TlsRecvFailed;
                            },
                        }
                    }

                    return @intCast(result);
                }
            }.recv,
            .send = struct {
                fn send(_: Socket, r: *Runtime, i: *anyopaque, b: []const u8) !usize {
                    const ctx: *VtableContext = @ptrCast(@alignCast(i));
                    ctx.cb_ctx.runtime = r;

                    const write_result = c.br_sslio_write(&ctx.sslio_ctx, b.ptr, b.len);
                    if (write_result < 0) {
                        const last_error = EngineStatus.convert(c.br_ssl_engine_last_error(&ctx.context.eng));
                        switch (last_error) {
                            .Ok, .InputOutput => return error.Closed,
                            else => {
                                log.err("sslio send failed: {s}", .{@tagName(last_error)});
                                return error.TlsSendFailed;
                            },
                        }
                    }

                    // Force flush. We should be buffering a layer above this.
                    const flush_result = c.br_sslio_flush(&ctx.sslio_ctx);
                    if (flush_result < 0) {
                        const last_error = EngineStatus.convert(c.br_ssl_engine_last_error(&ctx.context.eng));
                        switch (last_error) {
                            .Ok, .InputOutput => return error.Closed,
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
