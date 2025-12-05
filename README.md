# sraccoon

**sraccoon** is a blazingly fast RCON (Remote Console) utility written in [Zig](https://ziglang.org/), designed for managing game servers such as Minecraft. It provides a simple command-line interface for sending commands and receiving responses from any RCON-compatible server.

## Features

- ⚡ High performance, minimal resource usage (thanks to Zig)
- 🖥️ Command-line interface for interactive server management
- 🔒 Secure password authentication
- 📦 Supports any RCON-compatible game server (e.g., Minecraft, Rust)
- 🛠️ Easily configurable host, port, and password options

## Installation

### Prerequisites

- [Zig](https://ziglang.org/download/) (minimum version: 0.15.2)

### Build

Clone the repository and build the executable:

```sh
git clone https://github.com/yourusername/sraccoon.git
cd sraccoon
zig build
```

The compiled binary will be located in `zig-out/bin/`.

## Usage

Run the utility with your server details:

```sh
zig build run -- --host <server_ip> --port <rcon_port> --password <rcon_password>
```

- `--host`: Server IP address (default: 127.0.0.1)
- `--port`: RCON port (default: 25575)
- `--password`: RCON password (required)

Once connected, you'll be prompted to enter commands interactively. Responses from the server will be displayed in the terminal.

## Example

```sh
zig build run -- --host 192.168.1.100 --port 25575 --password mysecret
Enter a command: say Hello from sraccoon!
Command response: [Server] Hello from sraccoon!
```

## Dependencies

- [zig-cli](https://github.com/sam701/zig-cli) (for command-line parsing)

Dependencies are managed via `build.zig.zon`.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
