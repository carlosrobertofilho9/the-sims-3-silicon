# Marco 3 — abrir o launcher original

**Objetivo:** fazer aparecer a janela do launcher original do The Sims 3. Este marco não exige que o jogo comece.

## Estado atual

- Uma tentativa controlada pediu ao macOS para abrir o aplicativo instalado. Nenhuma janela apareceu; o próprio macOS recusou a abertura antes de iniciar o launcher.
- A mensagem do sistema foi `Launch failed` / `Launchd job spawn failed`.
- O diagnóstico local confirmou assinatura inválida: o selo não corresponde ao `Info.plist` e ao diretório de recursos, e a política de execução do macOS rejeita o pacote.
- O Rosetta está instalado. A falha desta tentativa, portanto, não demonstra se o Wine ou o launcher Windows de 32 bits funcionariam.
- Não pedimos para abrir o jogo nem fizemos alterações manuais na instalação.

## Próximo passo

Confirmar que a instalação vem íntegra de uma fonte legítima e, se necessário, restaurar o aplicativo por essa mesma fonte. Depois, repetir a abertura e verificar se a janela original aparece. Até o macOS aceitar o pacote, ainda não há uma estimativa confiável para chegar a uma janela funcionando.

## Limites da evidência

O resultado atual confirma uma recusa do macOS ao pacote instalado, não uma incompatibilidade comprovada do Wine nem uma falha interna do launcher. Nenhum arquivo do jogo, código proprietário, captura bruta ou caminho de instalação foi incluído neste repositório.
