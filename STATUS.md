# KingVCam iOS — Status / Handoff

**Data:** 2026-08-20  
**Branch:** `main` (último commit versionado antigo: `342ba2a` Release 2.2.0)  
**Objetivo deste arquivo:** outro agente/humano saber **onde paramos**, o que funciona, o que quebrou e o que **não** repetir.

---

## Onde paramos (agora)

| Item | Estado |
|------|--------|
| Site + API de chave (`kingvcam.com`) | OK (fluxo validado) |
| Tela de chave (SpringBoard / Gate) | OK |
| Volume ↑↓ → showgate → validar → ACK | OK na **2.2.31** |
| Injeção / substituição de câmera | OK na **2.2.31** |
| Controles da câmera (brilho, contraste, zoom…) | **AUSENTES** — problema aberto |
| Build **2.2.32** (botão Control no menu) | **TRAVOU** ao tocar em Control — **não usar** |

**Última versão válida para testar no device:**  
`dist/com.apple.avservicesd.rootless_2.2.31_volgate_iphoneos-arm64.deb`

**Última tentativa (quebrada):**  
`dist/com.apple.avservicesd.rootless_2.2.32_volgate_iphoneos-arm64.deb`  
→ Option A: botão Connect → label Control + `switchToControls` → **freeze**.

---

## Arquitetura (o que é o quê)

Pacote rootless `com.apple.avservicesd.rootless`:

1. **`AVServicesd.dylib`** — motor (injeção, menu Stream/USB/Galeria/Connect, painel de efeitos).  
   Base segura: motor da linha **2.2.0**, via deb  
   `dist/com.apple.avservicesd.rootless_2.2.18_gatepermfix_iphoneos-arm64.deb`  
   (mesmo motor + `license.json` / `showgate` já no binário).

2. **`KingVCamGate.dylib`** — tweak SpringBoard (`gate/Tweak.x`, Theos).  
   Escuta `com.kingvcam.showgate`, mostra tela de chave, valida em `kingvcam.com`, grava  
   `/var/jb/Library/KingVCam/license.json`, posta ACK `com.kingvcam.activated`.

3. **Site / servidor** — `server/` (API auth, admin, NOWPayments, debug log).  
   URLs relevantes:
   - `https://kingvcam.com` (loja / landing)
   - `https://kingvcam.com/v1/auth/login`
   - `https://kingvcam.com/v1/auth/validate`
   - `https://kingvcam.com/v1/debug/log` / `.../debug/read?device_id=ios`

---

## Fluxo desejado (produto)

1. Usuário no app de câmera → **volume ↑↓** (ou flutuante, conforme patch).  
2. Motor posta `com.kingvcam.showgate` e **espera** ACK (não reinicia mediaserverd no ACK do volume).  
3. Gate (SpringBoard) mostra **tela de chave**.  
4. Chave **válida** → license.json + `com.kingvcam.activated` → motor segue.  
5. Chave **inválida** → permanece na compra/chave; motor **não** libera.  
6. Com câmera injetada → usuário precisa dos **controles** (brilho/contraste/zoom). **Ainda não resolvido.**

---

## Pipeline de build atual

```text
python scripts/repack-gate-only.py
```

- Lê base: `2.2.18_gatepermfix`  
- Copia `gate/.theos/obj/debug/KingVCamGate.dylib` + plist  
- Patches no motor (`scripts/rebrand-pack.py`):
  - **Sempre:** `patch_license_live_revalidate` (volume/float → showgate → wait ACK)
  - **2.2.32 só:** `patch_menu_controls_button` (Connect → Control / `switchToControls`) — **CAUSOU FREEZE**
- Emite `dist/..._2.2.XX_volgate_iphoneos-arm64.deb`

Gate compila no WSL com Theos (`/home/gallzeraa/theos`), pasta `gate/`.

**Nota:** `dist/*` e `extracted/**` estão no `.gitignore` (bins locais). O handoff descreve os nomes dos `.deb`; eles existem na máquina do dono do repo.

---

## O que NÃO fazer de novo (já quebrou)

Patches agressivos de painel (evitar):

- `patch_panel_show_controls` (forçar ramo de controles / `menuCompact`)
- `patch_unlock_camera_controls` (forçar `panelVisible` / getters / NOP em `handleButtonTap:`)

Efeitos observados no passado:

- Botão flutuante “morto” (`handleButtonTap:` caía em hide early)
- Restart agressivo do `mediaserverd` no ACK (matava o processo antes do menu)
- UI inconsistente / crash

**Regra:** não inventar painel no motor além do mínimo; preservar fio volume → chave → ACK.

---

## Tentativa Option A (2.2.32) — detalhe técnico

Objetivo: botão na tela principal abrindo controles, sem patch de painel.

Implementação em `patch_menu_controls_button` (`scripts/rebrand-pack.py`):

- Labels `\x00 Connect\x00 Conectar\x00` → `\x00 Control\x00 Controle\x00`
- Nos 2 sites (por slice) que faziam `ldr` do selref `connectTapped` + `addTarget:`, passar a carregar selref `switchToControls`

Resultado no device: **trava ao tocar Control**.  
Hipótese a investigar: `switchToControls` assume painel/página já montada / `panelCentered`/`isVisible` / rebuild em estado inválido; ou target/`self` do UIButton não é o esperado em todos os layouts.

**Próximo agente:** reverter `repack-gate-only.py` para **não** chamar `patch_menu_controls_button` (voltar linha 2.2.31) antes de nova tentativa; ou isolar por que `switchToControls` freeza (disasm bloco `0x7e4f8` / async `0x7e580` no slice arm64).

---

## Última versão válida — checklist do que funciona (2.2.31)

Confirmado em uso real + log online:

- `notify_show_received` → `notify_show_revalidate_sync` → `validate_sync ok=1`
- `license_revalidated` → `activation_ack_posted_sync_no_restart`
- Injeção de imagem OK  
- Menu Stream/USB/Galeria/Connect aparece  
- **Controles/efeitos não aparecem**

Log debug: `https://kingvcam.com/v1/debug/read?device_id=ios`

---

## Arquivos-chave no working tree (muitos ainda sem commit histórico longo)

| Caminho | Papel |
|---------|--------|
| `STATUS.md` | Este handoff |
| `gate/Tweak.x` | Gate SpringBoard (chave, validate, ACK, debug HTTP) |
| `gate/Makefile`, `gate/control`, `gate/KingVCamGate.plist` | Build Theos |
| `scripts/repack-gate-only.py` | Gera deb volgate atual |
| `scripts/rebrand-pack.py` | Patches binários do motor |
| `scripts/extract-deb.py` | Extrai .deb → `extracted/` |
| `server/` | Backend kingvcam.com |
| `scripts/_*.py` | Helpers de disasm/análise (temporários) |

Git no início deste handoff: **quase só** o release 2.2.0 commitado; o resto estava untracked/modified. Este commit grava o status + fontes essenciais do gate/pack para o próximo agente não depender só da conversa.

---

## Pedido do produto (aberto)

Precisa de **controles da câmera** após injeção, **sem** quebrar:

1. Site / compra  
2. Tela de chave  
3. Volume → showgate → ACK  

Option A (botão) travou. Option B (controles sozinhos via patch de painel) já quebrou flutuante no passado — só com patch mínimo e teste cuidadoso.

---

## Como o próximo agente deve começar

1. Ler este `STATUS.md`.  
2. Instalar/testar a partir da **2.2.31**, não da 2.2.32.  
3. Em `repack-gate-only.py`, garantir que `patch_menu_controls_button` **não** entre no build “bom”.  
4. Só então investigar controles (UI nativa Menu/Filters/Controls, `rebuildPanel`, `menuCompact`, etc.) com mudanças mínimas e build incremental (2.2.33+).  
5. Confirmar com o usuário antes de patches grandes no motor (regra do dono do repo).
