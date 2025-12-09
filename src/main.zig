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
            std.debug.print("Write failure: {s}", .{@errorName(err)});
            return;
        };

        // TODO: Implement multi packet response using RESPONSEVALUE hack
        // Concat all packets together
        rd_bytes = client.read(&rbuf) catch |err| {
            std.debug.print("Read failure: {s}", .{@errorName(err)});
            return;
        };

        if (rd_bytes < rcon.RCON_PACKET_SIZE) {
            std.debug.print("Malformed response\n", .{});
        } else {
            const left_bytes: usize = rd_bytes - rcon.RCON_PACKET_SIZE;
            const resp_msg = rbuf[rcon.RCON_PACKET_SIZE .. rcon.RCON_PACKET_SIZE + left_bytes];
            std.debug.print("Command response: {s}\n", .{resp_msg});
        }
    }
}
