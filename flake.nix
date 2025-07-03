# Based upon https://github.com/the-nix-way/dev-templates
{
  description = "Basic Go + K8S development flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      goMajorVersion = 1;
      goMinorVersion = 24; # Change this to update the whole stack

      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSupportedSystem = f: nixpkgs.lib.genAttrs supportedSystems (system: f {
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ self.overlays.default ];
        };
      });
    in
    {
      overlays.default = final: prev: {
        go = final."go_${toString goMajorVersion}_${toString goMinorVersion}";
      };

      devShells = forEachSupportedSystem ({ pkgs }: {
        default = pkgs.mkShell {
          # Workaround CGO issue https://nixos.wiki/wiki/Go#Using_cgo_on_NixOS
          hardeningDisable = [ "fortify" ];

          packages = with pkgs; [
            # go
            go
            # goimports, godoc, etc.
            gotools
            gofumpt
            # https://github.com/golangci/golangci-lint
            golangci-lint

            # kubebuilder
            kubebuilder
          ];
        };
      });
    };

}
