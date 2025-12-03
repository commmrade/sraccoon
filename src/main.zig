const std = @import("std");

const PacketTypeError = error{TypeMismatch};
const SERVERDATA_AUTH_ID = 1;
const SEND_COMMAND_ID = 2;
const RCON_PACKET_MIN_SIZE = 10;
const RCON_PACKET_MAX_SIZE = 4096;
const RCON_PACKET_SIZE = @bitSizeOf(RconPacket) / 8;

const RconPacket = packed struct {
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

fn getCommandFromInp(stdin: *std.io.Reader, alloc: std.mem.Allocator) ![]u8 {
    std.debug.print("Enter a command: ", .{});
    const input = try stdin.takeDelimiterExclusive('\n');

    const command_str = try alloc.alloc(u8, input.len + 2);
    @memcpy(command_str[0..input.len], input);
    command_str[command_str.len - 2] = 0;
    command_str[command_str.len - 1] = 0;
    return command_str;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    const addr = try std.net.Address.parseIp("127.0.0.1", 25575);
    const sock = std.posix.socket(
        addr.any.family,
        std.posix.SOCK.STREAM,
        std.posix.IPPROTO.TCP,
    ) catch |err| {
        std.debug.print("Error creating socket: {s}\n", .{@errorName(err)});
        return err;
    };
    if (sock < 0) {
        return;
    }

    std.posix.connect(sock, &addr.any, addr.getOsSockLen()) catch |err| {
        std.debug.print("Error connecting to RCON: {s}\n", .{@errorName(err)});
        return;
    };

    defer std.posix.close(sock);

    var rbuf: [4096]u8 = undefined;

    var pswd_reader = std.fs.File.stdin().reader(&rbuf);
    const pswd_stdin = &pswd_reader.interface;

    const rcon_pass = try getPasswordFromInp(pswd_stdin, alloc);
    defer alloc.free(rcon_pass);

    const auth_packet = RconPacket{ .size = @intCast(RCON_PACKET_MIN_SIZE + rcon_pass.len - 2), .id = SERVERDATA_AUTH_ID, .type = 3 };

    const auth_packet_b = try auth_packet.build(rcon_pass, alloc);
    defer alloc.free(auth_packet_b);

    var wr_bytes = std.posix.write(sock, auth_packet_b) catch |err| {
        std.debug.print("Error writing to socket: {s}", .{@errorName(err)});
        return err;
    };

    var rd_bytes = std.posix.read(sock, &rbuf) catch |err| {
        std.debug.print("Error reading from socket: {s}", .{@errorName(err)});
        return err;
    };

    const auth_response_packet = std.mem.bytesToValue(RconPacket, rbuf[0..RCON_PACKET_SIZE]);
    if (auth_response_packet.id == -1) {
        std.debug.print("Was not authorized", .{});
        return;
    }
    // TODO: Handle errors gracefully

    std.debug.print("Authorized\n", .{});
    while (true) {
        var cmd_reader = std.fs.File.stdin().reader(&rbuf);
        const cmd_stdin = &cmd_reader.interface;

        const command_str = try getCommandFromInp(cmd_stdin, alloc);
        defer alloc.free(command_str);
        if (command_str.len > RCON_PACKET_MAX_SIZE - RCON_PACKET_SIZE) {
            std.debug.print("Input is too big to fit in a packet: {} bytes\n", .{command_str.len});
            return;
        }

        const command_packet = RconPacket{ .size = @intCast(RCON_PACKET_MIN_SIZE + command_str.len - 2), .id = SEND_COMMAND_ID, .type = 2 };
        const command_packet_b = try command_packet.build(command_str, alloc);
        defer alloc.free(command_packet_b);

        // TODO: Write in several writes
        wr_bytes = std.posix.write(sock, command_packet_b) catch |err| {
            std.debug.print("Error writing to socket: {s}\n", .{@errorName(err)});
            return;
        };

        // TODO: Packet split in several reads
        rd_bytes = std.posix.read(sock, &rbuf) catch |err| {
            std.debug.print("Error reading from socket: {s}\n", .{@errorName(err)});
            return;
        };

        const resp_packet = std.mem.bytesToValue(RconPacket, rbuf[0..RCON_PACKET_SIZE]);
        std.debug.print("Response packet: {}\n", .{resp_packet});
        if (rd_bytes < RCON_PACKET_SIZE) {
            std.debug.print("Malformed response\n", .{});
        } else {
            const left_bytes: usize = rd_bytes - RCON_PACKET_SIZE;
            std.debug.print("Command response: {s}\n", .{rbuf[RCON_PACKET_SIZE .. RCON_PACKET_SIZE + left_bytes]});
        }
    }
}
