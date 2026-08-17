# Relatorio de extracao .deb

- Gerado em: `2026-08-17 11:13:55` (mapeamento atualizado em seguida)
- Arquivo: `com.apple.avservicesd.rootless_2.0.994_iphoneos-arm64.deb`
- Caminho: `C:\kingvcamios\incoming\com.apple.avservicesd.rootless_2.0.994_iphoneos-arm64.deb`
- Tamanho: 611.8 KB

## Control

- **Package:** `com.apple.avservicesd.rootless`
- **Name:** LordVCAM (Rootless)
- **Version:** 2.0.994
- **Architecture:** `iphoneos-arm64`
- **Depends:** `mobilesubstrate | ellekit | libhooker | substitute`
- **Description:** Virtual camera — palera1n rootless / Dopamine 1 (arm64)
- **Author / Maintainer:** Apple Inc. (rotulo do pacote)

## Pacote clonado KingVCam

Clone visual do 2.0.994, injecao e caminhos `com.apple.*` iguais.

- Script: `scripts/rebrand-pack.py`
- Saida: `dist/com.apple.avservicesd.rootless_2.0.997_iphoneos-arm64.deb`
- **Version:** 2.1.0
- AUTH_BYPASS: gate + estado=1 + NOP paywall. Painel de ferramentas abre mesmo sem moeda/login.
- AUTH_BYPASS: gate 0x5f0 + estado=1 + NOP login/currency/wallet/alert/sync. `AUTH_BYPASS=False` religa o original.
- AUTH_BYPASS: gate 0x5f0 + UI estado forçado=1 (sem login/plano). `AUTH_BYPASS=False` no script religa o fluxo original.
- License/login: gate `0x5f0` forçado (tbnz -> b). Camera funciona sem credencial; auth novo fica para o servidor depois.
- Icone: `assets/kingvcam-icon.png` → `/var/jb/Library/KingVCam/icon.png`
- **Name:** KingVCam (Rootless)
- **Author:** KingVCam
- **Version:** 2.0.996
- Accent UI: `systemBlueColor` → `systemMintColor`
- Strings: `LordVCAM` → `KingVCam`, `lordvcam.com` → `kingvcam.com`
- Package ID Debian (para substituir o original): `com.apple.avservicesd.rootless`

## Mapa do tweak

Nao e um daemon `avservicesd` substituido. E um **tweak Cydia Substrate rootless** chamado **LordVCAM**, instalado em `/var/jb`.

```
incoming/*.deb
        |
        +-- control/
        |     control     metadados Debian
        |     postinst    cria IPC + killall daemons (respring parcial)
        |     postrm      limpa cache/prefs na remocao
        |
        +-- data/var/jb/Library/MobileSubstrate/DynamicLibraries/
              AVServicesd.dylib   payload Mach-O fat (arm64 + arm64e)
              AVServicesd.plist   filtro de injecao
              AVServicesd.sig     assinatura Substrate (12 bytes)
```

### Onde injeta (`AVServicesd.plist`)

Filter:

- Bundles: `com.apple.mediaserverd`, `com.apple.springboard`, `com.apple.lskdd`, `com.apple.UIKit`
- Executables: `mediaserverd`, `lskdd`

Ou seja: pipeline de camera (`mediaserverd` / FigCapture), SpringBoard (UI/gestos) e processos UIKit.

### Binario

- `AVServicesd.dylib` — Mach-O **fat**, 2.9 MB
  - slice 0: **arm64** (`cpu=0x100000c`, `sub=0x0`), 1.40 MB
  - slice 1: **arm64e** (`cpu=0x100000c`, `sub=0x80000002`), 1.43 MB
- Linka: AVFoundation, CoreVideo, VideoToolbox, AVFAudio, CydiaSubstrate (`MSHookMessageEx`)
- Frameworks privados referenciados: `CMCapture`, `CMCaptureCore`

### IPC / prefs

| Caminho | Uso |
|---|---|
| `/var/tmp/com.apple.avfcache` | diretorio IPC (criado no `postinst`, `chmod 777`) |
| `/var/tmp/com.apple.avfcache/crash.txt` | log de crash |
| `/var/mobile/Library/Preferences/com.apple.avsd.plist` | preferencias (apagado no `postrm`) |
| `com.apple.avsd` | bundle de settings |
| `com.apple.avsd.gps` / `.gps.real` / `.gps.ext` | GPS virtual vs real |
| `com.apple.avsd.vmirror` | espelhamento |
| `com.apple.avsd.capture` | upload de captura |
| `com.apple.avsd.debuglog` | debug |

### Scripts Debian

`postinst`: cria `/var/tmp/com.apple.avfcache` e mata, nesta ordem, `mediaserverd` → `PosterBoard` / `ExtragalacticPoster` / `lskdd` → `backboardd` (KeepAlive relanca).

`postrm`: so em `remove|purge` apaga o cache IPC e `com.apple.avsd.plist` (upgrade preserva tokens/prefs).

### Pipeline interno (classes AVS*)

Fonte de frames:

- `AVSLocalDataProvider` — video local via `AVAssetReader` (`setupVideoReader`, `nextVideoFrame`)
- `AVSRemoteDataProvider` — frames remotos
- `AVSStreamTransport` / `AVSLocalTransport` — transporte (WebSocket `wss://%@:%d`, `WSServer` local)
- `AVSMediaDecoder` — decode
- `AVSFrameCoordinator` / `AVSRenderPipeline` / `AVSFormatAnalyzer` — resize, filtros, cache 30 fps
- `AVSAudioBridge` — audio
- `AVSMotionSynthesizer` — movimento sintetico
- `AVSPreferencePanel` / `AVSPresentationController` / `AVSMapController` — UI no SpringBoard

Pontos citados no binario (FigCapture / camera): `FigCaptureClientSessionMonitor`, `BWNodeOutput`, `AVCaptureConnection`, `AVCapturePhotoOutput`, `BWVideoOrientationMetadataNode`.

UI SpringBoard citada: `VolumeHook`, `HomeButtonHook`, `SwipeHomeHook`, `KYCSpringBoard`.

### Rede / licenca

- UI: "LordVCAM Server is running on PC"
- Limite: `lordvcam.com/member`
- Auth/captura: `/auth/capture/presign`, `/auth/capture/register` (upload R2)
- Anti-analise: mensagens para Frida, debugger e tweak conflitante

### `.sig`

Conteudo ASCII: `aHRqdGNjbg==` (12 bytes). Stub de assinatura Substrate, nao e codesign Apple.

## Arquivos de control

- `./control`
- `./postinst`
- `./postrm`

## Binarios Mach-O

- `var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib` — Mach-O fat, arch=arm64+arm64e, 2.9 MB

## dylibs

- `var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib` — 2.9 MB

## plists

- `var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.plist` — keys: Filter

## scripts

- `control/postinst`
- `control/postrm`

## Arvore data/

| Caminho | Tipo | Tamanho |
|---|---|---|
| `var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.dylib` | Mach-O fat | 2.9 MB |
| `var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.plist` | plist-binary | 200 B |
| `var/jb/Library/MobileSubstrate/DynamicLibraries/AVServicesd.sig` | sig | 12 B |
