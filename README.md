# secsock 

This is an implementation of `SecureSocket`, a wrapper for the Tardy `Socket` type that provides TLS functionality.

## Supported TLS Backends
- [s2n-tls](https://github.com/aws/s2n-tls): An implementation of SSL/TLS protocols by AWS.

## Installing
Compatible Zig Version: `0.14.0`

Compatible [tardy](https://github.com/tardy-org/tardy) Version: `019a81d00efc01157b9c67c357e53fcf75e48e6e`

Latest Release: `0.0.0`
```
zig fetch --save git+https://github.com/tardy-org/secsock#v0.0.0
```

You can then add the dependency in your `build.zig` file:
```zig
const secsock = b.dependency("secsock", .{
    .target = target,
    .optimize = optimize,
}).module("secsock");

exe.root_module.addImport(secsock);
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
git clone https://github.com/tardy-org/secsock.git
cd secsock
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

