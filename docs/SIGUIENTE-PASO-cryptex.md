# Siguiente paso: el Cryptex1,SystemOS (dyld shared cache)

## Dónde estamos (hito enorme, ya logrado)
El iOS 27 COMPLETO bootea por SPTM/XNU, monta su **root filesystem real** (md0,
apfs mountroot) y arranca `/sbin/launchd` (PID 1). El fix del md0 (6 instrucciones
w→x, firmware/bootkc.md0) eliminó la truncación de 32 bits que impedía montar.

## El único bloqueo ahora
`launchd[1]` panica: *"Library not loaded: /usr/lib/libSystem.B.dylib … no dyld cache"*.

**Causa (confirmada al 100%):** el rootfs `094-13182-141` es el **SystemOS partido**.
NO contiene los dylibs del sistema ni el `dyld_shared_cache`. Evidencia:
- `/usr/lib/libSystem.B.dylib` NO existe (solo la variante `_asan`).
- `/private/preboot/Cryptexes/` está VACÍO.
- `dyld` busca el cache en `/System/Cryptexes/OS` → `/private/preboot/Cryptexes/OS/`.

Esos dylibs + el shared cache viven en el **Cryptex1,SystemOS** (~2.3GB), que NO
está descargado. Presentes localmente: rootfs (094-13182-141), ExclaveOS
(094-14052-182), restore ramdisk (094-13753-197). Falta: el Cryptex1,SystemOS.

## Qué tenés que hacer vos (firmware handling = tu parte)
1. Del IPSW de 24A5430a / iPhone17,3, tomá el componente **Cryptex1,SystemOS**
   (el `.dmg.aea` de ~2.3GB — el mismo tipo de AEA que ya descifraste para el rootfs).
2. Descifralo con el mismo método/clave que usaste para 094-13182-141.dmg.aea.

## Qué hace el tooling (ya listo)
    ./inject_cryptex.sh /ruta/al/Cryptex1_SystemOS_descifrado.dmg
Esto convierte el rootfs a escribible, mete el cryptex en
`/private/preboot/Cryptexes/OS`, verifica que aparezca `dyld_shared_cache*` y
`libSystem.B.dylib`, y deja `firmware/rootfs_with_cryptex.dmg`.

Luego arrancá:
    ROOTFS=firmware/rootfs_with_cryptex.dmg ./run_rootfs.sh
(run_rootfs.sh ya usa bootkc.md0 por defecto → monta root).

## Expectativa honesta después del cryptex
launchd va a encontrar libSystem y a arrancar daemons. Pero **SpringBoard (el UI)
necesita la GPU AGX**, que NO está emulada en darwin-vm/qemu. Así que tras el
cryptex esperamos: más daemons arrancando y luego faults/panics en servicios que
tocan hardware no emulado (GPU, varios coprocesadores). La "pantalla" que sí
renderiza hoy es el panel del DCP emulado con el LOG de boot real (Boot A).
El camino a píxeles reales de UI = emular AGX + decodificar superficies IOMFB en
apple_dcp.c, ambos gigantes y también gated por el cryptex.
