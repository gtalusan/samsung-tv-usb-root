{
  description = "One-plug Samsung T-MSMDEUC USB root exploit and research lab";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
    in {
      packages = forAllSystems (pkgs:
        let
          runtime = with pkgs; [
            python3 qemu dosfstools exfatprogs mtools util-linux e2fsprogs
            file binutils openssh
            ropgadget python3Packages.ropper
            pkgsCross.arm-embedded.buildPackages.binutils
          ];
          armSoftMusl = import nixpkgs {
            localSystem = pkgs.stdenv.hostPlatform.system;
            crossSystem = {
              config = "armv7l-unknown-linux-musleabi";
              gcc = { arch = "armv7-a"; tune = "cortex-a15"; float = "soft"; };
            };
          };
          dropbearTv = armSoftMusl.pkgsStatic.stdenv.mkDerivation {
            pname = "dropbear-tv";
            version = "2022.83";
            src = pkgs.fetchurl {
              url = "https://matt.ucc.asn.au/dropbear/releases/dropbear-2022.83.tar.bz2";
              hash = "sha256-vFoSH/vJS1FxrV6+Ab5CdG1Qqnl8lUmkY5iUoWdJRDs=";
            };
            patches = [ ./payload/dropbear-authorized-keys-opt.patch ];
            buildInputs = [ armSoftMusl.pkgsStatic.libxcrypt ];
            env.CFLAGS = "-Os -march=armv7-a -mtune=cortex-a15 -mfloat-abi=soft -ffunction-sections -fdata-sections";
            env.LDFLAGS = "-static -Wl,--gc-sections";
            configureFlags = [
              "--disable-zlib" "--disable-syslog" "--disable-lastlog"
              "--disable-utmp" "--disable-utmpx" "--disable-wtmp"
              "--disable-wtmpx" "--disable-pututline" "--disable-pututxline"
            ];
            preBuild = ''
              makeFlagsArray+=("PROGRAMS=dropbear dropbearkey scp" "MULTI=1" "SCPPROGRESS=0")
            '';
            enableParallelBuilding = true;
            installPhase = ''
              runHook preInstall
              install -Dm755 dropbearmulti $out/bin/dropbearmulti
              runHook postInstall
            '';
            postFixup = ''
              ${armSoftMusl.stdenv.cc.bintools}/bin/${armSoftMusl.stdenv.cc.targetPrefix}strip \
                --strip-all $out/bin/dropbearmulti
            '';
          };
          mkUsb = pkgs.writeShellApplication {
            name = "mk-samsung-tv-usb";
            runtimeInputs = runtime;
            text = ''exec ${pkgs.python3}/bin/python ${self}/tools/mk_usb_stick.py --dropbear ${dropbearTv}/bin/dropbearmulti "$@"'';
          };
        in {
          default = mkUsb;
          mk-samsung-tv-usb = mkUsb;
          dropbear-tv = dropbearTv;
        });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.mk-samsung-tv-usb}/bin/mk-samsung-tv-usb";
          meta.description = "Build a Samsung T-MSMDEUC USB-root image";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            python3 qemu dosfstools exfatprogs mtools util-linux e2fsprogs
            file binutils openssh git
            ropgadget python3Packages.ropper
            python3Packages.capstone python3Packages.pwntools
            pkgsCross.arm-embedded.buildPackages.binutils
          ];
          shellHook = ''echo "samsung-tv-usb-root: mk-samsung-tv-usb --help"'';
        };
      });
    };
}
