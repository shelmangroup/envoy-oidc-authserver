{
  description = "Shelman Authz";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }: flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
    in 
    {
      devShell = pkgs.mkShell {
        buildInputs = (with pkgs; [
          delve
          git
          go_1_21
          go-task
          golangci-lint
          golines
          gotestsum
          jless
          ko
          watchexec
        ]);
      };
    }
  );
}
