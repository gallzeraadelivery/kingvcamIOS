# KingVCam iOS 3.0.44-14 — versão oficial

Confirmada pelo proprietário em 2026-10-06 no iPhone de teste: login, menu, atalho de volume e substituição da câmera funcionando.

Pacote: `dist/com.apple.avservicesd.rootless_3.0.44-14_kingvcam-minimal_iphoneos-arm64.deb`

SHA-256: `5ff308d049f9de3eed34f4f46b6ef2fd29c756db55a77471cdec839ec4640d88`

Base: pacote original 3.0.44 confirmado funcional no mesmo aparelho, SHA-256 `7ffab80997c84e168e9a3448f559c6bd6b6805c837d14242de72b7e070c22af7`.

Mudança de runtime: URLs codificadas da API e do site/repositório apontam para `www.kingvcam.com`; instruções executáveis do motor e filtro de injeção permanecem iguais às do original. O pacote mantém os direitos originais do daemon e aplica assinatura na instalação.

Verificação: `python scripts/test-minimal-api.py` (3 testes) e `python scripts/audit-package-api.py dist/com.apple.avservicesd.rootless_3.0.44-14_kingvcam-minimal_iphoneos-arm64.deb`.

Não substituir por versões experimentais 3.0.44-12 ou anteriores. Esta confirmação prática é do aparelho testado pelo proprietário; outros dispositivos e versões de iOS não foram validados.
