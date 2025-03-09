# secsock 

This is an implementation of `SecureSocket`, a wrapper for the Tardy `Socket` type that provides TLS functionality.

## Supported TLS Backends:
- [s2n-tls](https://github.com/aws/s2n-tls): An implementation of SSL/TLS protocols by AWS.

## Installing
Latest Release: `0.0.0`

Compatible Zig Version: `0.13.0`

Compatible [tardy](https://github.com/tardy-org/tardy) Version: `ef40de9e16c300d883a3e9dade648a6d1cff209d` 
```
zig fetch --save git+https://github.com/tardy-org/tls#v0.0.0
```

You can then add the dependency in your `build.zig` file:
```zig
const tls = b.dependency("tls", .{
    .target = target,
    .optimize = optimize,
}).module("tls");

exe.root_module.addImport(tls);
```

## Contribution
We use Nix Flakes for managing the development environment. Nix Flakes provide a reproducible, declarative approach to managing dependencies and development tools.

### Prerequisites
 - Install [Nix](https://nixos.org/download/)
```bash 
sh <(curl -L https://nixos.org/nix/install) --daemon
```
 - Enable [Flake support](https://nixos.wiki/wiki/Flakes) in your Nix config (`~/.config/nix/nix.conf`): `experimental-features = nix-command flakes`

### Getting Started
1. Clone this repository:
```bash
git clone https://github.com/tardy-org/tls.git
cd tls
```

2. Enter the development environment:
```bash
nix develop
```

This will provide you with a shell that contains all of the necessary tools and dependencies for development.

Once you are inside of the development shell, you can update the development dependencies by:
1. Modifying the `flake.nix`
2. Running `nix flake update`
3. Committing both the `flake.nix` and the `flake.lock`

### License
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in secsock by you, shall be licensed as MPL2.0, without any additional terms or conditions.

