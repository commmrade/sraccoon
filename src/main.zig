const std = @import("std");
const rcon = @import("rcon.zig");

const PacketTypeError = error{TypeMismatch};
const ClientError = error{ ConnectFailed, SockCreationFailed };

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
    var rbuf: [4096]u8 = undefined;

    var client = rcon.RconClient.connect("127.0.0.1", 25575, alloc) catch |err| {
        std.debug.print("Connection failure: {s}\n", .{@errorName(err)});
        return;
    };
    defer client.close();

    var pswd_reader = std.fs.File.stdin().reader(&rbuf);
    const pswd_stdin = &pswd_reader.interface;

    const rcon_pass = try getPasswordFromInp(pswd_stdin, alloc);
    defer alloc.free(rcon_pass);

    const auth_packet = rcon.RconPacket{ .size = @intCast(rcon.RCON_PACKET_MIN_SIZE + rcon_pass.len - 2), .id = rcon.SERVERDATA_AUTH_ID, .type = 3 };

    const auth_packet_b = try auth_packet.build(rcon_pass, alloc);
    defer alloc.free(auth_packet_b);

    var wr_bytes = client.write(auth_packet_b) catch |err| {
        std.debug.print("Write failure: {s}", .{@errorName(err)});
        return err;
    };

    var rd_bytes = client.read(&rbuf) catch |err| {
        std.debug.print("Read failure: {s}", .{@errorName(err)});
        return err;
    };

    const auth_response_packet = std.mem.bytesToValue(rcon.RconPacket, rbuf[0..rcon.RCON_PACKET_SIZE]);
    if (auth_response_packet.id == -1) {
        std.debug.print("Was not authorized", .{});
        return;
    }

    std.debug.print("Authorized\n", .{});
    while (true) {
        var cmd_reader = std.fs.File.stdin().reader(&rbuf);
        const cmd_stdin = &cmd_reader.interface;

        const command_str = try getCommandFromInp(cmd_stdin, alloc);
        defer alloc.free(command_str);
        if (command_str.len > rcon.RCON_PACKET_MAX_SIZE - rcon.RCON_PACKET_SIZE) {
            std.debug.print("Input is too big to fit in a packet: {} bytes\n", .{command_str.len});
            return;
        }

        const command_packet = rcon.RconPacket{ .size = @intCast(rcon.RCON_PACKET_MIN_SIZE + command_str.len - 2), .id = rcon.SEND_COMMAND_ID, .type = 2 };
        const command_packet_b = try command_packet.build(command_str, alloc);
        defer alloc.free(command_packet_b);

        // TODO: Write in several writes
        wr_bytes = client.write(command_packet_b) catch |err| {
            std.debug.print("Write failure: {s}", .{@errorName(err)});
            return;
        };

        // TODO: Packet split in several reads
        rd_bytes = client.read(&rbuf) catch |err| {
            std.debug.print("Read failure: {s}", .{@errorName(err)});
            return;
        };

        const resp_packet = std.mem.bytesToValue(rcon.RconPacket, rbuf[0..rcon.RCON_PACKET_SIZE]);
        std.debug.print("Response packet: {}\n", .{resp_packet});
        if (rd_bytes < rcon.RCON_PACKET_SIZE) {
            std.debug.print("Malformed response\n", .{});
        } else {
            const left_bytes: usize = rd_bytes - rcon.RCON_PACKET_SIZE;
            std.debug.print("Command response: {s}\n", .{rbuf[rcon.RCON_PACKET_SIZE .. rcon.RCON_PACKET_SIZE + left_bytes]});
        }
    }
}
