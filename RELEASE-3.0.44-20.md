# KingVCam iOS 3.0.44-20 — ponto de restauração

Pacote exato: `dist/com.apple.avservicesd.rootless_3.0.44-20_iphoneos-arm64.deb`

SHA-256: `e83357e2e642b7ba55bcb37b3fc1a6c00ac82054696fb5903a0e725ed0c744a4`

Origem imutável: 3.0.44-19, SHA-256 `3084934c41742af6bf210894f21348000eda0a07186a42609d6a8abf9043cd55`.

Únicas diferenças em relação à 3.0.44-19: inclusão do bundle
`com.doordash.dasher` no filtro `AVServicesd.plist` e atualização de
`Version` no controle Debian. O motor, daemon, API, scripts de instalação e
todos os outros arquivos internos são idênticos. Três testes automatizados
comparam integralmente os arquivos dos dois pacotes.

O proprietário informou em 2026-10-08 que a câmera virtual funciona no
Dasher. A versão 3.0.44-19 já havia sido confirmada no app Câmera, Safari e
DuckDuckGo, incluindo reinício e novo jailbreak. Um teste de reinício da
3.0.44-20 deve ser registrado separadamente.

Para restaurar, reinstale este pacote exato e confira o SHA-256. Para voltar
à versão anterior, use a tag Git `v3.0.44-19` ou o snapshot anterior do
repositório Sileo no servidor.
