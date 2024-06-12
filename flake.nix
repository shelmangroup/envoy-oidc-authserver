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
        buf
        delve
        git
        go_1_22
        go-task
        golangci-lint
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
