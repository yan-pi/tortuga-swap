{
  description = "tortuga-swap — dev environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      # `nix develop` (or direnv via .envrc) drops you into this shell.
      #
      # We use mkShellNoCC on purpose: class_group's build.rs vendors PARI/GP
      # and compiles it from source, and PARI's ./Configure expects a
      # conventional system `cc`. nix's clang wrapper breaks that link step,
      # so we keep the macOS Xcode toolchain and only layer on the libraries
      # and tools macOS lacks. The Rust toolchain also stays global (rustup),
      # so bacon / rust-analyzer keep working unchanged.
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            # gmp: required by rust-gmp-kzen (cl-crypto -> class_group -> curv).
            pkgs.gmp

            # pkg-config: lets build scripts discover gmp via gmp.pc.
            pkgs.pkg-config

            # bison: class_group's vendored PARI/GP needs bison 3.x to
            # process parse.y. macOS only ships bison 2.3.
            pkgs.bison

            # Rust toolchain
            pkgs.rustup

            # C compiler for PARI/GP build (use gcc14 for compatibility)
            pkgs.gcc14

            # OpenSSL for reqwest (esplora client)
            pkgs.openssl

            # libclang for bindgen (class_group)
            pkgs.llvmPackages.libclang

            # python + scientific stack for the statistical pipeline in
            # analysis/ (generate_synthetic.py, run.py).
            (pkgs.python3.withPackages (ps: with ps; [
              numpy
              pandas
              scipy
            ]))
          ];

          # With no cc-wrapper, point the system compiler/linker at gmp.
          shellHook = ''
            export LIBRARY_PATH="${pkgs.gmp}/lib''${LIBRARY_PATH:+:$LIBRARY_PATH}"
            export CPATH="${pkgs.gmp.dev}/include:${pkgs.glibc.dev}/include''${CPATH:+:$CPATH}"
            export PKG_CONFIG_PATH="${pkgs.gmp.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
            export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
            export LDFLAGS="-lc ''${LDFLAGS:+$LDFLAGS}"
          '';
        };
      });
    };
}
