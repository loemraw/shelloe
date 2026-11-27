{
  lib,
  buildGoModule,
  fetchurl,
  openssh,
}:
let
  # The files scripts/vendor-xterm.json pins, written into the page's vendor directory as
  # scripts/vendor-xterm.py writes them.
  vendorXterm = lib.concatMapStrings (
    pin:
    let
      tarball = fetchurl {
        url = "https://registry.npmjs.org/${pin.name}/-/${baseNameOf pin.name}-${pin.version}.tgz";
        hash = pin.integrity;
      };
    in
    lib.concatStrings (
      lib.mapAttrsToList (member: name: ''
        tar -xzf ${tarball} -O ${member} > $web/vendor/${name}
      '') pin.files
    )
  ) (lib.importJSON ./scripts/vendor-xterm.json);
in
buildGoModule {
  pname = "shelloe";
  version = "0-unstable";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./cmd
      ./e2e
      ./internal
      # Not what the README's build writes into web/, which a source other than a git checkout has.
      (lib.fileset.difference ./web (
        lib.fileset.unions [
          (lib.fileset.maybeMissing ./web/vendor)
          (lib.fileset.maybeMissing ./web/shelloe.wasm)
          (lib.fileset.maybeMissing ./web/wasm_exec.js)
        ]
      ))
      ./go.mod
      ./go.sum
    ];
  };
  vendorHash = "sha256-tykFqaom1/TETUT+Drc7cpe2VxatLOhdFZhvZ/q5ym0=";

  env.CGO_ENABLED = 0;
  subPackages = [ "cmd/shelloe" ];
  ldflags = [
    "-s"
    "-w"
  ];

  postBuild = ''
    GOOS=js GOARCH=wasm go build -o shelloe.wasm ./cmd/shelloe-wasm
  '';

  # Every package's tests, not only the server's. Those that need sshd or Chrome skip.
  nativeCheckInputs = [ openssh ];
  checkPhase = ''
    runHook preCheck
    go test ./...
    runHook postCheck
  '';

  postInstall = ''
    web=$out/share/shelloe/web
    mkdir -p $web/vendor
    cp web/* shelloe.wasm "$(go env GOROOT)/lib/wasm/wasm_exec.js" $web/
    ${vendorXterm}
  '';

  meta.mainProgram = "shelloe";
}
