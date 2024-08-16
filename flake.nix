{
  description = "Envoy OIDC Authserver";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }: 
    utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
        inherit system;
      };
      devPkgs = with pkgs; [
        (golangci-lint.override { buildGoModule = buildGo123Module; })
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
      devShells = {
        default = pkgs.mkShell {
          LOCALE_ARCHIVE = "${pkgs.glibcLocales}/lib/locale/locale-archive";
          packages = devPkgs;
        };
      };
    }
  );
}
