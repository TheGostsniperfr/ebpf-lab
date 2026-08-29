{
  description = "eBPF learning lab: a minimal XDP packet counter loaded from Go";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            # The nixpkgs cc-wrapper injects hardening flags (stack-protector,
            # fortify, PIE) that the BPF backend rejects. bpf2go must be
            # pointed at the unwrapped compiler via BPF2GO_CC below.
            llvmPackages.clang-unwrapped
            llvm # llvm-strip, used by bpf2go to drop DWARF from the object
            libbpf # bpf/bpf_helpers.h, bpf/bpf_endian.h
            linuxHeaders # linux/bpf.h, linux/if_ether.h, linux/ip.h (kernel uapi)
            iproute2 # `ip link` to find interface names / attach points
          ];

          BPF2GO_CC = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
          BPF2GO_STRIP = "${pkgs.llvm}/bin/llvm-strip";
          BPF2GO_CFLAGS = "-O2 -g -Wall -Werror -I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include";
        };
      });
}
