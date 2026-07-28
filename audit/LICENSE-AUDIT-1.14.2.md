# Auditoría de licencias de ZeroTier One 1.14.2

- Commit auditado: `185a3a2c76e6bf1b1c0415871f43076638eb007c`
- Archivos rastreados: **1799**
- Archivos inspeccionados directamente por ScanCode: **1785**
- Metadatos o enlaces clasificados únicamente por alcance: **14**
- Archivos que requieren revisión manual: **100**
- Errores del escáner: **0**
- Herramienta de detección: ScanCode Toolkit 32.5.0, umbral 70

## Resultado por licencia efectiva

| Archivos | Licencia o conclusión |
|---:|---|
| 763 | `BSD-3-Clause` |
| 441 | `Apache-2.0 (effective 2026-01-01; formerly BUSL-1.1)` |
| 281 | `Apache-2.0` |
| 100 | `NOASSERTION` |
| 79 | `GPL-3.0-or-later` |
| 57 | `MIT` |
| 29 | `GPL-2.0-only` |
| 20 | `GPL-3.0-or-later AND GPL-3.0-only` |
| 6 | `LicenseRef-Public-Domain` |
| 4 | `GPL-2.0-or-later WITH Autoconf-exception-generic` |
| 4 | `LicenseRef-scancode-public-domain` |
| 4 | `MS-PL` |
| 2 | `BSD-2-Clause` |
| 2 | `GPL-3.0-or-later WITH Autoconf-exception-generic-3.0 AND LicenseRef-scancode-warranty-disclaimer` |
| 1 | `X11 AND LicenseRef-scancode-public-domain` |
| 1 | `GPL-2.0-or-later WITH Libtool-exception AND GPL-3.0-or-later WITH Libtool-exception AND GPL-3.0-or-later` |
| 1 | `(FSFULLR AND GPL-2.0-or-later WITH Libtool-exception) AND FSFUL` |
| 1 | `FSFUL AND GPL-2.0-or-later WITH Libtool-exception` |
| 1 | `Apache-2.0 AND BSD-2-Clause` |
| 1 | `BSD-3-Clause AND BSD-2-Clause` |
| 1 | `BSD-1-Clause` |

## Nivel de confianza

| Archivos | Nivel |
|---:|---|
| 1683 | `high` |
| 100 | `review` |
| 16 | `medium` |

## Casos que requieren revisión

Estos archivos están en subárboles externos para los que no se encontró una
declaración de licencia aplicable. No deben copiarse al port hasta aclarar su
procedencia o reemplazarlos.

- `attic/WinUI/Fonts/segoeui.ttf`
- `attic/WinUI/Fonts/segoeuib.ttf`
- `ext/README.md`
- `ext/bin/tap-windows-ndis6/arm64/zttap300.cat`
- `ext/bin/tap-windows-ndis6/arm64/zttap300.inf`
- `ext/bin/tap-windows-ndis6/arm64/zttap300.sys`
- `ext/bin/tap-windows-ndis6/x64/zttap300.cat`
- `ext/bin/tap-windows-ndis6/x64/zttap300.inf`
- `ext/bin/tap-windows-ndis6/x64/zttap300.sys`
- `ext/bin/tap-windows-ndis6/x86/zttap300.cat`
- `ext/bin/tap-windows-ndis6/x86/zttap300.inf`
- `ext/bin/tap-windows-ndis6/x86/zttap300.sys`
- `ext/central-controller-docker/Dockerfile`
- `ext/central-controller-docker/Dockerfile.builder`
- `ext/central-controller-docker/Dockerfile.run_base`
- `ext/central-controller-docker/Makefile`
- `ext/central-controller-docker/README.md`
- `ext/central-controller-docker/main.sh`
- `ext/ed25519-amd64-asm/batch.c`
- `ext/ed25519-amd64-asm/choose_t.s`
- `ext/ed25519-amd64-asm/consts.s`
- `ext/ed25519-amd64-asm/fe25519.h`
- `ext/ed25519-amd64-asm/fe25519_add.s`
- `ext/ed25519-amd64-asm/fe25519_freeze.s`
- `ext/ed25519-amd64-asm/fe25519_getparity.c`
- `ext/ed25519-amd64-asm/fe25519_invert.c`
- `ext/ed25519-amd64-asm/fe25519_iseq.c`
- `ext/ed25519-amd64-asm/fe25519_iszero.c`
- `ext/ed25519-amd64-asm/fe25519_mul.s`
- `ext/ed25519-amd64-asm/fe25519_neg.c`
- `ext/ed25519-amd64-asm/fe25519_pack.c`
- `ext/ed25519-amd64-asm/fe25519_pow2523.c`
- `ext/ed25519-amd64-asm/fe25519_setint.c`
- `ext/ed25519-amd64-asm/fe25519_square.s`
- `ext/ed25519-amd64-asm/fe25519_sub.s`
- `ext/ed25519-amd64-asm/fe25519_unpack.c`
- `ext/ed25519-amd64-asm/ge25519.h`
- `ext/ed25519-amd64-asm/ge25519_add.c`
- `ext/ed25519-amd64-asm/ge25519_add_p1p1.s`
- `ext/ed25519-amd64-asm/ge25519_base.c`
- `ext/ed25519-amd64-asm/ge25519_base_niels.data`
- `ext/ed25519-amd64-asm/ge25519_base_niels_smalltables.data`
- `ext/ed25519-amd64-asm/ge25519_base_slide_multiples.data`
- `ext/ed25519-amd64-asm/ge25519_dbl_p1p1.s`
- `ext/ed25519-amd64-asm/ge25519_double.c`
- `ext/ed25519-amd64-asm/ge25519_double_scalarmult.c`
- `ext/ed25519-amd64-asm/ge25519_isneutral.c`
- `ext/ed25519-amd64-asm/ge25519_multi_scalarmult.c`
- `ext/ed25519-amd64-asm/ge25519_nielsadd2.s`
- `ext/ed25519-amd64-asm/ge25519_nielsadd_p1p1.s`
- `ext/ed25519-amd64-asm/ge25519_p1p1_to_p2.s`
- `ext/ed25519-amd64-asm/ge25519_p1p1_to_p3.s`
- `ext/ed25519-amd64-asm/ge25519_pack.c`
- `ext/ed25519-amd64-asm/ge25519_pnielsadd_p1p1.s`
- `ext/ed25519-amd64-asm/ge25519_scalarmult_base.c`
- `ext/ed25519-amd64-asm/ge25519_unpackneg.c`
- `ext/ed25519-amd64-asm/heap_rootreplaced.s`
- `ext/ed25519-amd64-asm/heap_rootreplaced_1limb.s`
- `ext/ed25519-amd64-asm/heap_rootreplaced_2limbs.s`
- `ext/ed25519-amd64-asm/heap_rootreplaced_3limbs.s`
- `ext/ed25519-amd64-asm/hram.c`
- `ext/ed25519-amd64-asm/hram.h`
- `ext/ed25519-amd64-asm/implementors`
- `ext/ed25519-amd64-asm/index_heap.c`
- `ext/ed25519-amd64-asm/index_heap.h`
- `ext/ed25519-amd64-asm/keypair.c`
- `ext/ed25519-amd64-asm/open.c`
- `ext/ed25519-amd64-asm/sc25519.h`
- `ext/ed25519-amd64-asm/sc25519_add.s`
- `ext/ed25519-amd64-asm/sc25519_barrett.s`
- `ext/ed25519-amd64-asm/sc25519_from32bytes.c`
- `ext/ed25519-amd64-asm/sc25519_from64bytes.c`
- `ext/ed25519-amd64-asm/sc25519_from_shortsc.c`
- `ext/ed25519-amd64-asm/sc25519_iszero.c`
- `ext/ed25519-amd64-asm/sc25519_lt.s`
- `ext/ed25519-amd64-asm/sc25519_mul.c`
- `ext/ed25519-amd64-asm/sc25519_mul_shortsc.c`
- `ext/ed25519-amd64-asm/sc25519_slide.c`
- `ext/ed25519-amd64-asm/sc25519_sub_nored.s`
- `ext/ed25519-amd64-asm/sc25519_to32bytes.c`
- `ext/ed25519-amd64-asm/sc25519_window4.c`
- `ext/ed25519-amd64-asm/sign.c`
- `ext/ed25519-amd64-asm/ull4_mul.s`
- `ext/installfiles/linux/zerotier-containerized/Dockerfile`
- `ext/installfiles/linux/zerotier-containerized/main.sh`
- `ext/installfiles/linux/zerotier-one.init.rhel6`
- `ext/installfiles/linux/zerotier-one.te`
- `ext/installfiles/mac-update/updater.tmpl.sh`
- `ext/installfiles/mac/ZeroTier One.pkgproj`
- `ext/installfiles/mac/com.zerotier.one.plist`
- `ext/installfiles/mac/get-proxy-settings.sh`
- `ext/installfiles/mac/launch.sh`
- `ext/installfiles/mac/postinst.sh`
- `ext/installfiles/mac/preinst.sh`
- `ext/installfiles/mac/uninstall.sh`
- `ext/installfiles/windows/ZeroTier One Virtual Network Port (NDIS6_x64).aip`
- `ext/installfiles/windows/ZeroTier One Virtual Network Port (NDIS6_x86).aip`
- `ext/installfiles/windows/ZeroTier One.aip`
- `ext/installfiles/windows/ZeroTier One.back.aip`
- `ext/misc/linux-old-glibc-compat.c`

## Criterio aplicado

La detección directa identifica textos o avisos dentro del archivo. Cuando un
archivo carece de aviso, se aplica solamente una licencia de paquete respaldada
por un LICENSE/COPYING o una declaración inequívoca. El resto del árbol propio
se clasifica bajo la BSL 1.1 del repositorio, cuya Change Date fue 2026-01-01 y
cuya Change License declarada es Apache-2.0. Esta clasificación no resuelve la
ambigüedad jurídica de que el campo Licensed Work mencione la versión 1.4.4.

El CSV es el resultado canónico archivo por archivo.
