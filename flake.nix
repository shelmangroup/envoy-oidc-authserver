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
        inherit (nixpkgs) lib;

        pkgs = import nixpkgs {
          inherit system;
        };
        devPkgs = with pkgs; [
          golangci-lint
          buf
          delve
          git
          go_1_24
          gopls
          go-task
          golines
          goreleaser
          gotestsum
          glibcLocales
          ko
          protobuf
          protoc-gen-go
          watchexec
          mkcert
        ];
      in
      {

        packages = rec {
          default = pkgs.buildGo123Module {
            pname = "envoy-oidc-authserver";
            version = "main";
            src = ./.;

            ldflags = [ "-s -w" ];
            CGO_ENABLED = "0";

            meta = {
              description = "Envoy OIDC Authserver";
              homepage = "https://github.com/shelmangroup/envoy-oidc-authserver";
              mainProgram = "envoy-oidc-authserver";
            };

            # vendorHash = ""; # Use this when upgrading dependencies
            vendorHash = "sha256-n7+O+uc8YRnhXccVVnKE6zK8kh8EGiKeiES4A+R1Dhg=";

            nativeBuildInputs = with pkgs; [
              buf
              protoc-gen-go
            ];

            prePatch = ''
              HOME="$TMPDIR" ${pkgs.buf}/bin/buf generate
            '';

            postInstall = ''
              ${pkgs.upx}/bin/upx $out/bin/envoy-oidc-authserver
            '';
          };

          container = pkgs.dockerTools.buildImage {
            name = "envoy-oidc-authserver";
            tag = "latest";
            copyToRoot = [ default ];
            config.Entrypoint = [ "${default}/bin/envoy-oidc-authserver" ];
          };
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
