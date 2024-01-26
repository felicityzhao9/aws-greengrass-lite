{ lib, ... }: {
  inputsFrom = pkgs: [ pkgs.default ];
  packages = pkgs: with pkgs; ([
    coreutils
    clang-tools_16
    cppcheck
    cmake-format
    fd
    git
    git-secrets
    (python3.withPackages (ps: with ps; [ yapf python-lsp-server ]))
  ] ++ (lib.optionals (!pkgs.stdenv.isDarwin) [
    gdb
  ]));
  env = {
    CMAKE_EXPORT_COMPILE_COMMANDS = "1";
    NIX_HARDENING_ENABLE = "";
  };
}
