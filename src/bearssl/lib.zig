const std = @import("std");
const assert = std.debug.assert;

const tardy = @import("tardy");
const Socket = tardy.Socket;
const Runtime = tardy.Runtime;

const SecureSocket = @import("../lib.zig").SecureSocket;

const log = std.log.scoped(.bearssl);

const c = @cImport({
    @cInclude("bearssl.h");
});

pub const EngineStatus = enum {
    Ok,
    BadParam,
    BadState,
    UnsupportedVersion,
    BadVersion,
    TooLarge,
    BadMac,
    NoRandom,
    UnknownType,
    Unexpected,
    BadCcs,
    BadAlert,
    BadHandshake,
    OversizedId,
    BadCipherSuite,
    BadCompression,
    BadFragLen,
    BadSecretReneg,
    ExtraExtension,
    BadSNI,
    BadHelloDone,
    LimitExceeded,
    BadFinished,
    ResumeMismatch,
    InvalidAlgorithm,
    BadSignature,
    WrongKeyUsage,
    NoClientAuth,
    InputOutput,
    RecvFatal,
    SendFatal,
    Unknown,

    pub fn convert(status_code: c_int) EngineStatus {
        return switch (status_code) {
            c.BR_ERR_OK => .Ok,
            c.BR_ERR_BAD_PARAM => .BadParam,
            c.BR_ERR_BAD_STATE => .BadState,
            c.BR_ERR_UNSUPPORTED_VERSION => .UnsupportedVersion,
            c.BR_ERR_BAD_VERSION => .BadVersion,
            c.BR_ERR_TOO_LARGE => .TooLarge,
            c.BR_ERR_BAD_MAC => .BadMac,
            c.BR_ERR_NO_RANDOM => .NoRandom,
            c.BR_ERR_UNKNOWN_TYPE => .UnknownType,
            c.BR_ERR_UNEXPECTED => .Unexpected,
            c.BR_ERR_BAD_CCS => .BadCcs,
            c.BR_ERR_BAD_ALERT => .BadAlert,
            c.BR_ERR_BAD_HANDSHAKE => .BadHandshake,
            c.BR_ERR_OVERSIZED_ID => .OversizedId,
            c.BR_ERR_BAD_CIPHER_SUITE => .BadCipherSuite,
            c.BR_ERR_BAD_COMPRESSION => .BadCompression,
            c.BR_ERR_BAD_FRAGLEN => .BadFragLen,
            c.BR_ERR_BAD_SECRENEG => .BadSecretReneg,
            c.BR_ERR_EXTRA_EXTENSION => .ExtraExtension,
            c.BR_ERR_BAD_SNI => .BadSNI,
            c.BR_ERR_BAD_HELLO_DONE => .BadHelloDone,
            c.BR_ERR_LIMIT_EXCEEDED => .LimitExceeded,
            c.BR_ERR_BAD_FINISHED => .BadFinished,
            c.BR_ERR_RESUME_MISMATCH => .ResumeMismatch,
            c.BR_ERR_INVALID_ALGORITHM => .InvalidAlgorithm,
            c.BR_ERR_BAD_SIGNATURE => .BadSignature,
            c.BR_ERR_WRONG_KEY_USAGE => .WrongKeyUsage,
            c.BR_ERR_NO_CLIENT_AUTH => .NoClientAuth,
            c.BR_ERR_IO => .InputOutput,
            c.BR_ERR_RECV_FATAL_ALERT => .RecvFatal,
            c.BR_ERR_SEND_FATAL_ALERT => .SendFatal,
            else => .Unknown,
        };
    }
};

pub const BearSSL = struct {
    pub const PrivateKey = union(enum) {
        rsa: c.br_rsa_private_key,
        ec: c.br_ec_private_key,
    };

    allocator: std.mem.Allocator,
    x509: ?c.br_x509_certificate,
    pkey: ?PrivateKey,
    cert_signer_algo: ?c_int,
    // Client verification / trust
    trust_anchors: std.ArrayListUnmanaged(c.br_x509_trust_anchor) = .{},
    owned_anchors: std.ArrayListUnmanaged(OwnedAnchor) = .{},
    sni_server_name: ?[]u8 = null,

    const OwnedAnchor = union(enum) {
        rsa: struct { dn: []u8, n: []u8, e: []u8 },
        ec: struct { dn: []u8, q: []u8 },
    };

    pub fn init(allocator: std.mem.Allocator) BearSSL {
        return .{
            .allocator = allocator,
            .x509 = null,
            .pkey = null,
            .cert_signer_algo = null,
            .trust_anchors = .{},
            .owned_anchors = .{},
            .sni_server_name = null,
        };
    }

    pub fn deinit(self: *BearSSL) void {
        if (self.x509) |x509| self.allocator.free(x509.data[0..x509.data_len]);

        if (self.pkey) |pkey| switch (pkey) {
            .rsa => |inner| {
                self.allocator.free(inner.p[0..inner.plen]);
                self.allocator.free(inner.q[0..inner.qlen]);
                self.allocator.free(inner.dp[0..inner.dplen]);
                self.allocator.free(inner.dq[0..inner.dqlen]);
                self.allocator.free(inner.iq[0..inner.iqlen]);
            },
            .ec => |inner| {
                self.allocator.free(inner.x[0..inner.xlen]);
            },
        };

        // free trust anchors
        for (self.owned_anchors.items) |owned| switch (owned) {
            .rsa => |inner| {
                self.allocator.free(inner.dn);
                self.allocator.free(inner.n);
                self.allocator.free(inner.e);
            },
            .ec => |inner| {
                self.allocator.free(inner.dn);
                self.allocator.free(inner.q);
            },
        };
        self.trust_anchors.deinit(self.allocator);
        self.owned_anchors.deinit(self.allocator);
        if (self.sni_server_name) |sni| self.allocator.free(sni);
    }

    /// This takes in the PEM section and the given bytes and decodes it into a byte format
    /// that can be ingested later by the BearSSL x509 certificate.
    fn decode_pem(allocator: std.mem.Allocator, section_title: ?[]const u8, bytes: []const u8) ![]const u8 {
        var p_ctx: c.br_pem_decoder_context = undefined;
        c.br_pem_decoder_init(&p_ctx);

        var decoded = try std.ArrayListUnmanaged(u8).initCapacity(allocator, bytes.len);
        defer decoded.deinit(allocator);

        c.br_pem_decoder_setdest(&p_ctx, struct {
            fn decoder(ctx: ?*anyopaque, src: ?*const anyopaque, size: usize) callconv(.c) void {
                var list: *std.ArrayListUnmanaged(u8) = @ptrCast(@alignCast(ctx.?));
                const data = @as([*c]const u8, @ptrCast(src.?))[0..size];
                list.appendSliceAssumeCapacity(data);
            }
        }.decoder, &decoded);

        var found = false;
        var written: usize = 0;

        while (written < bytes.len) {
            written += c.br_pem_decoder_push(&p_ctx, bytes[written..].ptr, bytes.len - written);
            const event = c.br_pem_decoder_event(&p_ctx);
            switch (event) {
                0 => continue,
                c.BR_PEM_BEGIN_OBJ => {
                    const name = c.br_pem_decoder_name(&p_ctx);
                    if (section_title) |title| {
                        if (std.mem.eql(u8, std.mem.span(name), title)) {
                            found = true;
                            decoded.clearRetainingCapacity();
                        }
                    } else found = true;
                },
                c.BR_PEM_END_OBJ => if (found) return decoded.toOwnedSlice(allocator),
                c.BR_PEM_ERROR => return error.PemDecodeFailed,
                else => return error.PemDecodeUnknownEvent,
            }
        }

        return error.PemDecodeNotFinished;
    }

    fn decode_private_key(allocator: std.mem.Allocator, decoded_key: []const u8) !PrivateKey {
        var sk_ctx: c.br_skey_decoder_context = undefined;
        c.br_skey_decoder_init(&sk_ctx);
        c.br_skey_decoder_push(&sk_ctx, decoded_key.ptr, decoded_key.len);

        if (c.br_skey_decoder_last_error(&sk_ctx) != 0) return error.PrivateKeyDecodeFailed;
        const key_type = c.br_skey_decoder_key_type(&sk_ctx);

        return switch (key_type) {
            c.BR_KEYTYPE_RSA => key: {
                const key = c.br_skey_decoder_get_rsa(&sk_ctx)[0];

                const p = try allocator.dupe(u8, key.p[0..key.plen]);
                errdefer allocator.free(p);

                const q = try allocator.dupe(u8, key.q[0..key.qlen]);
                errdefer allocator.free(q);

                const dp = try allocator.dupe(u8, key.dp[0..key.dplen]);
                errdefer allocator.free(dp);

                const dq = try allocator.dupe(u8, key.dq[0..key.dqlen]);
                errdefer allocator.free(dq);

                const iq = try allocator.dupe(u8, key.iq[0..key.iqlen]);
                errdefer allocator.free(iq);

                break :key .{
                    .rsa = .{
                        .p = p.ptr,
                        .plen = key.plen,
                        .q = q.ptr,
                        .qlen = key.qlen,
                        .dp = dp.ptr,
                        .dplen = key.dplen,
                        .dq = dq.ptr,
                        .dqlen = key.dqlen,
                        .iq = iq.ptr,
                        .iqlen = key.iqlen,
                        .n_bitlen = key.n_bitlen,
                    },
                };
            },
            c.BR_KEYTYPE_EC => key: {
                const key = c.br_skey_decoder_get_ec(&sk_ctx)[0];
                const x = try allocator.dupe(u8, key.x[0..key.xlen]);
                errdefer allocator.free(x);

                break :key .{
                    .ec = .{
                        .x = x.ptr,
                        .xlen = key.xlen,
                        .curve = key.curve,
                    },
                };
            },
            else => return error.InvalidKeyType,
        };
    }

    fn get_cert_signer_algo(x509: *const c.br_x509_certificate) c_int {
        var x509_ctx: c.br_x509_decoder_context = undefined;

        c.br_x509_decoder_init(&x509_ctx, null, null);
        c.br_x509_decoder_push(&x509_ctx, x509.data.?, x509.data_len);
        if (c.br_x509_decoder_last_error(&x509_ctx) != 0) return 0;
        return c.br_x509_decoder_get_signer_key_type(&x509_ctx);
    }

    pub fn add_cert_chain(
        self: *BearSSL,
        cert_section_title: ?[]const u8,
        cert: []const u8,
        key_section_title: ?[]const u8,
        key: []const u8,
    ) !void {
        const decoded_cert = try decode_pem(self.allocator, cert_section_title, cert);
        errdefer self.allocator.free(decoded_cert);
        self.x509 = .{ .data = @constCast(decoded_cert.ptr), .data_len = decoded_cert.len };

        const decoded_key = try decode_pem(self.allocator, key_section_title, key);
        defer self.allocator.free(decoded_key);
        self.pkey = try decode_private_key(self.allocator, decoded_key);

        self.cert_signer_algo = get_cert_signer_algo(&self.x509.?);
    }

    /// Add a single trust anchor from a DER-encoded certificate (CA or leaf).
    pub fn add_trust_anchor_der(self: *BearSSL, der: []const u8) !void {
        var dn_buf = std.ArrayListUnmanaged(u8){};
        defer dn_buf.deinit(self.allocator);

        // Collect subject DN while decoding cert
        var xdc: c.br_x509_decoder_context = undefined;
        c.br_x509_decoder_init(&xdc, struct {
            fn append_dn(ctx: ?*anyopaque, buf: ?*const anyopaque, len: usize) callconv(.c) void {
                var list: *std.ArrayListUnmanaged(u8) = @ptrCast(@alignCast(ctx.?));
                const src = @as([*c]const u8, @ptrCast(buf.?))[0..len];
                list.appendSliceAssumeCapacity(src);
            }
        }.append_dn, &dn_buf);

        try dn_buf.ensureTotalCapacity(self.allocator, der.len);
        c.br_x509_decoder_push(&xdc, der.ptr, der.len);
        if (c.br_x509_decoder_last_error(&xdc) != 0) return error.X509DecodeFailed;

        const pkey_ptr = c.br_x509_decoder_get_pkey(&xdc);
        if (pkey_ptr == null) return error.X509NoPublicKey;
        const pkey = pkey_ptr.*;

        const is_ca: bool = (c.br_x509_decoder_isCA(&xdc) != 0);

        var anchor: c.br_x509_trust_anchor = undefined;
        var owned: OwnedAnchor = undefined;

        const dn = try dn_buf.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(dn);
        anchor.dn = .{ .data = dn.ptr, .len = dn.len };
        anchor.flags = if (is_ca) c.BR_X509_TA_CA else 0;

        switch (pkey.key_type) {
            c.BR_KEYTYPE_RSA => {
                // Copy RSA components
                const n = try self.allocator.dupe(u8, pkey.key.rsa.n[0..pkey.key.rsa.nlen]);
                errdefer self.allocator.free(n);
                const e = try self.allocator.dupe(u8, pkey.key.rsa.e[0..pkey.key.rsa.elen]);
                errdefer self.allocator.free(e);

                anchor.pkey.key_type = c.BR_KEYTYPE_RSA;
                anchor.pkey.key.rsa = .{
                    .n = n.ptr,
                    .nlen = pkey.key.rsa.nlen,
                    .e = e.ptr,
                    .elen = pkey.key.rsa.elen,
                };

                owned = .{ .rsa = .{ .dn = dn, .n = n, .e = e } };
            },
            c.BR_KEYTYPE_EC => {
                const q = try self.allocator.dupe(u8, pkey.key.ec.q[0..pkey.key.ec.qlen]);
                errdefer self.allocator.free(q);

                anchor.pkey.key_type = c.BR_KEYTYPE_EC;
                anchor.pkey.key.ec = .{
                    .curve = pkey.key.ec.curve,
                    .q = q.ptr,
                    .qlen = pkey.key.ec.qlen,
                };

                owned = .{ .ec = .{ .dn = dn, .q = q } };
            },
            else => return error.UnsupportedKeyType,
        }

        try self.trust_anchors.append(self.allocator, anchor);
        try self.owned_anchors.append(self.allocator, owned);
    }

    /// Decode a PEM certificate and add as trust anchor.
    pub fn add_trust_anchor_pem(self: *BearSSL, section_title: ?[]const u8, pem_bytes: []const u8) !void {
        const der = try decode_pem(self.allocator, section_title orelse "CERTIFICATE", pem_bytes);
        defer self.allocator.free(der);
        try self.add_trust_anchor_der(der);
    }

    /// Set SNI server name for client connections.
    pub fn set_sni(self: *BearSSL, name: []const u8) !void {
        if (self.sni_server_name) |old| self.allocator.free(old);
        self.sni_server_name = try self.allocator.dupe(u8, name);
    }

    pub fn to_secure_socket(self: *BearSSL, socket: Socket, mode: SecureSocket.Mode) !SecureSocket {
        switch (mode) {
            .client => return @import("client.zig").to_secure_socket_client(self, socket),
            .server => return @import("server.zig").to_secure_socket_server(self, socket),
        }
    }
};
