{
  description = "Envoy OIDC Authserver";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      utils,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        devPkgs = with pkgs; [
          golangci-lint
          buf
          delve
          git
          go_1_23
          go-task
          golines
          goreleaser
          gotestsum
          glibcLocales
          ko
          protobuf
          protoc-gen-go
          watchexec
        ];
      in
      {
        packages.default = pkgs.buildGo123Module {
          pname = "envoy-oidc-authserver";
          version = "main";
          src = ./.;

          # vendorHash = ""; # Use this when upgrading dependencies
          vendorHash = "sha256-n7+O+uc8YRnhXccVVnKE6zK8kh8EGiKeiES4A+R1Dhg=";

          nativeBuildInputs = with pkgs; [
            buf
            protoc-gen-go
          ];

          prePatch = ''
            HOME="$TMPDIR" ${pkgs.buf}/bin/buf generate
          '';
        };

        devShells = {
          default = pkgs.mkShell {
            LOCALE_ARCHIVE = "${pkgs.glibcLocales}/lib/locale/locale-archive";
            packages = devPkgs;
          };
        };
      }
    );
}
