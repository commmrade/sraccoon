const std = @import("std");

const PacketTypeError = error{TypeMismatch};

const RconPacket = packed struct {
    size: i32,
    id: i32,
    type: i32,

    pub fn build(self: *const RconPacket, body: ?[]const u8, alloc: std.mem.Allocator) ![]u8 {
        const auth_packet_b = try alloc.alloc(u8, @bitSizeOf(RconPacket) / 8 + if (body == null) 0 else body.?.len);
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

const SERVERDATA_AUTH_ID = 1;
const SEND_COMMAND_ID = 2;
const RCON_PACKET_MIN_SIZE = 10;

/// Allocates
fn getPasswordFromInp(stdin: *std.io.Reader, alloc: std.mem.Allocator) ![]u8 {
    std.debug.print("Enter your password: ", .{});
    const pass_input = try stdin.takeDelimiterExclusive('\n');
    const command_str = try alloc.alloc(u8, pass_input.len + 2);
    @memcpy(command_str[0..pass_input.len], pass_input);
    command_str[command_str.len - 2] = 0;
    command_str[command_str.len - 1] = 0;
    return command_str;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    const addr = try std.net.Address.parseIp("127.0.0.1", 25575);
    const sock = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);

    try std.posix.connect(sock, &addr.any, addr.getOsSockLen());
    defer std.posix.close(sock);

    var rbuf: [1024]u8 = undefined;

    var stdin_reader = std.fs.File.stdin().reader(&rbuf);
    const stdin = &stdin_reader.interface;

    const rcon_pass = try getPasswordFromInp(stdin, alloc);

    const auth_packet = RconPacket{ .size = @intCast(RCON_PACKET_MIN_SIZE + rcon_pass.len - 2), .id = SERVERDATA_AUTH_ID, .type = 3 };

    const auth_packet_b = try auth_packet.build(rcon_pass, alloc);
    defer alloc.free(auth_packet_b);

    _ = try std.posix.write(sock, auth_packet_b);

    _ = try std.posix.read(sock, &rbuf);

    const auth_response_packet = std.mem.bytesToValue(RconPacket, rbuf[0 .. @bitSizeOf(RconPacket) / 8]);
    if (auth_response_packet.id == -1) {
        std.debug.print("Was not authorized", .{});
        return;
    }

    std.debug.print("Authorized\n", .{});
    // std.debug.print("Response: {}\n", .{auth_response_packet});

    while (true) {
        @memset(&rbuf, 0);

        std.debug.print("Enter a command: ", .{});
        const input = try stdin.takeDelimiterExclusive('\n');
        // std.debug.print("Cm: '{s}' {}\n", .{ input, input.len });
        const command_str = try alloc.alloc(u8, input.len + 2);
        defer alloc.free(command_str);
        // FIXME: Reads 1 byte more than supposed to
        @memcpy(command_str[0..input.len], input);
        command_str[command_str.len - 2] = 0;
        command_str[command_str.len - 1] = 0;

        const command_packet = RconPacket{ .size = @intCast(RCON_PACKET_MIN_SIZE + command_str.len - 2), .id = SEND_COMMAND_ID, .type = 2 };
        const command_packet_b = try command_packet.build(command_str, alloc);
        std.debug.print("Cm: '{s}' {}\n", .{ command_str, command_str.len });
        _ = try std.posix.write(sock, command_packet_b); // TODO: What if cant write in 1 write, need to split it
        // std.debug.print("Written comm bytes: {}, {}, {}\n", .{ wr_bytes, command_packet, command_packet_b.len });

        const rd_bytes = try std.posix.read(sock, &rbuf); // TODO: This may not come in 1 read, so need a way to make sure it all comes, timeout?

        // const command_response_packet = std.mem.bytesToValue(RconPacket, rbuf[0 .. @bitSizeOf(RconPacket) / 8]);
        const left_bytes = rd_bytes - @bitSizeOf(RconPacket) / 8;
        std.debug.print("Command response: {s}", .{rbuf[@bitSizeOf(RconPacket) / 8 .. @bitSizeOf(RconPacket) / 8 + left_bytes]});
    }
}
