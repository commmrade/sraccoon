const std = @import("std");
const rcon = @import("rcon.zig");
const cli = @import("cli");

const PacketTypeError = error{TypeMismatch};
const ClientError = error{ ConnectFailed, SockCreationFailed };

fn getCommandFromInp(stdin: *std.io.Reader) ![]u8 {
    std.debug.print("Enter a command: ", .{});
    const input = try stdin.takeDelimiterExclusive('\n');
    return input;
}

var config = struct { host: []const u8 = "127.0.0.1", port: u16 = 25575, password: []const u8 = "" }{};

pub fn main() !void {
    var r = try cli.AppRunner.init(std.heap.page_allocator);

    const app = cli.App{ .command = cli.Command{ .name = "server settings", .options = try r.allocOptions(&.{ .{ .long_name = "host", .help = "Host to listen on", .value_ref = r.mkRef(&config.host) }, .{ .long_name = "port", .help = "Port to bind to", .value_ref = r.mkRef(&config.port) }, .{ .long_name = "password", .help = "RCON Password", .required = true, .value_ref = r.mkRef(&config.password) } }), .target = cli.CommandTarget{
        .action = cli.CommandAction{ .exec = run },
    } } };
    return r.run(&app);
}

pub fn run() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    var rbuf: [4096]u8 = undefined;

    var client = rcon.RconClient.connect(config.host, config.port, alloc) catch |err| {
        std.debug.print("Connection failure: {s}\n", .{@errorName(err)});
        return;
    };
    defer client.close();

    const auth_packet = rcon.RconPacket{ .size = @intCast(rcon.RCON_PACKET_MIN_SIZE + config.password.len), .id = rcon.SERVERDATA_AUTH_ID, .type = 3 };

    const auth_packet_b = try auth_packet.build(config.password, alloc);
    defer alloc.free(auth_packet_b);

    var wr_bytes = client.write_all(auth_packet_b) catch |err| {
        std.debug.print("Write failure: {s}", .{@errorName(err)});
        return err;
    };

    var rd_bytes = client.read(&rbuf) catch |err| {
        std.debug.print("Read failure: {s}", .{@errorName(err)});
        return err;
    };

    const auth_response_packet = std.mem.bytesToValue(rcon.RconPacket, rbuf[0..rcon.RCON_PACKET_SIZE]);
    if (auth_response_packet.id == -1) {
        std.debug.print("Was not authorized\n", .{});
        return;
    }

    std.debug.print("Authorized\n", .{});
    while (true) {
        var cmd_reader = std.fs.File.stdin().reader(&rbuf);
        const cmd_stdin = &cmd_reader.interface;

        const command_str = try getCommandFromInp(cmd_stdin);
        if (command_str.len > rcon.RCON_PACKET_MAX_SIZE - rcon.RCON_PACKET_SIZE) {
            std.debug.print("Input is too big to fit in a packet: {} bytes\n", .{command_str.len});
            return;
        }

        const command_packet = rcon.RconPacket{ .size = @intCast(rcon.RCON_PACKET_MIN_SIZE + command_str.len), .id = rcon.SEND_COMMAND_ID, .type = 2 };
        const command_packet_b = try command_packet.build(command_str, alloc);
        defer alloc.free(command_packet_b);

        wr_bytes = client.write_all(command_packet_b) catch |err| {
            std.debug.print("Write failure: {s}\n", .{@errorName(err)});
            return;
        };

        const response_value_packet = rcon.RconPacket{ .size = @intCast(rcon.RCON_PACKET_MIN_SIZE + 8), .id = 999, .type = 0 };

        const body: [8]u8 = [8]u8{ 0, 0, 0, 1, 0, 0, 0, 0 };
        const body_slice = body[0..];

        const response_value_packet_b = try response_value_packet.build(body_slice, alloc);
        wr_bytes = client.write_all(response_value_packet_b) catch |err| {
            std.debug.print("Write failure: {s}\n", .{@errorName(err)});
            return;
        };

        var rd_packets = std.ArrayList([]u8){}; // Store all packets
        defer rd_packets.deinit(alloc);

        while (true) {
            rd_bytes = client.read(&rbuf) catch |err| {
                std.debug.print("Read failure: {s}\n", .{@errorName(err)});
                return;
            };
            const pkt = std.mem.bytesToValue(rcon.RconPacket, rbuf[0..rcon.RCON_PACKET_SIZE]);
            const payload_len = rd_bytes - rcon.RCON_PACKET_SIZE;
            if (pkt.id == 999) { // If we get the INCORRECT packet, then we received everything, break the loop
                break;
            } else {
                const payload = try alloc.dupe(u8, rbuf[rcon.RCON_PACKET_SIZE..][0..payload_len]);
                try rd_packets.append(alloc, payload);
            }
        }

        var response = std.ArrayList(u8){};
        defer response.deinit(alloc);

        for (rd_packets.items) |part| { // Order may be wrong, since packets are sent back async, but idc really
            try response.appendSlice(alloc, part);
        }

        std.debug.print("Command response: {s}\n", .{response.items});
    }
}
