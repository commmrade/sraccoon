const std = @import("std");

pub const SERVERDATA_AUTH_ID = 1;
pub const SEND_COMMAND_ID = 2;
pub const RCON_PACKET_MIN_SIZE = 10;
pub const RCON_PACKET_MAX_SIZE = 4096;
pub const RCON_PACKET_SIZE = @bitSizeOf(RconPacket) / 8;

pub const RconPacket = packed struct {
    size: i32,
    id: i32,
    type: i32,

    pub fn build(self: *const RconPacket, body: ?[]const u8, alloc: std.mem.Allocator) ![]u8 {
        const auth_packet_b = try alloc.alloc(u8, RCON_PACKET_SIZE + if (body == null) 0 else body.?.len);
        var idx: usize = 0;

        std.mem.writePackedInt(i32, auth_packet_b[idx .. idx + @sizeOf(i32)], 0, self.size, std.builtin.Endian.little);
        idx += @sizeOf(i32);

        std.mem.writePackedInt(i32, auth_packet_b[idx .. idx + @sizeOf(i32)], 0, self.id, std.builtin.Endian.little);
        idx += @sizeOf(i32);

        std.mem.writePackedInt(i32, auth_packet_b[idx .. idx + @sizeOf(i32)], 0, self.type, std.builtin.Endian.little);
        idx += @sizeOf(i32);

        if (body != null) {
            @memcpy(auth_packet_b[idx .. idx + body.?.len], body.?.ptr);
        }

        return auth_packet_b;
    }
};

pub const RconClient = struct {
    sock: i32,
    alloc: std.mem.Allocator,
    const Self = @This();
    pub fn connect(ip: []const u8, port: u16, alloc: std.mem.Allocator) !RconClient {
        const addr = try std.net.Address.parseIp(ip, port);
        const sock = try std.posix.socket(
            addr.any.family,
            std.posix.SOCK.STREAM,
            std.posix.IPPROTO.TCP,
        );
        const client = RconClient{ .sock = sock, .alloc = alloc };

        try std.posix.connect(client.sock, &addr.any, addr.getOsSockLen());

        return client;
    }
    pub fn close(self: *Self) void {
        std.posix.close(self.sock);
    }

    pub fn write(self: *Self, buf: []const u8) !usize {
        const wr_bytes = try std.posix.write(self.sock, buf);
        return wr_bytes;
    }
    pub fn read(self: *Self, buf: []u8) !usize {
        const rd_bytes = std.posix.read(self.sock, buf);
        return rd_bytes;
    }
};
