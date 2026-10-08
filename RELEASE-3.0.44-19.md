# KingVCam iOS 3.0.44-19 — ponto de restauração

Pacote exato: `dist/com.apple.avservicesd.rootless_3.0.44-19_iphoneos-arm64.deb`

SHA-256: `3084934c41742af6bf210894f21348000eda0a07186a42609d6a8abf9043cd55`

Origem imutável: 3.0.44-14, SHA-256 `5ff308d049f9de3eed34f4f46b6ef2fd29c756db55a77471cdec839ec4640d88`.

O motor, daemon, API e scripts de instalação são byte a byte iguais aos da
3.0.44-14. A 3.0.44-19 altera somente o filtro de injeção e o campo `Version`
do pacote. O filtro inclui Câmera, SpringBoard, Safari, WebContent, WebKit GPU,
mediaserverd e assetsd; exclui UIKit genérico e `lskdd`, que havia registrado
crashes repetidos. `python -B scripts/test-webkit-camera.py` valida as diferenças
de todos os arquivos dentro do pacote.

Confirmação do proprietário em 2026-10-08: a substituição da imagem funciona
na Câmera nativa e em testes de webcam no Safari e DuckDuckGo. O Live Motion
continua funcionando na Câmera nativa, mas não no navegador — limitação
conhecida, deixada intacta neste release. Não há mudança no servidor de login
nem na API de pagamento neste release.

Para restaurar este ponto, reinstale o pacote exato acima e confira o SHA-256.
Para voltar ao ponto anterior, use a tag Git `v3.0.44-14` e seu pacote indicado
em `RELEASE-3.0.44-14.md`. A publicação no Sileo deve manter um snapshot
recuperável do índice anterior no servidor.

O teste de reinício com jailbreak deve ser confirmado separadamente antes de
considerar esta versão validada para outros aparelhos.
