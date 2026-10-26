# Marco 4 — executar uma fixture PE32 no interpretador

Este marco conecta o carregador PE32 ao subconjunto x86 interpretado em ARM64. A fixture foi escrita para este laboratório em [pe32_execution_fixture.hpp](../lab/tests/pe32_execution_fixture.hpp); nenhum arquivo ou recurso do jogo é carregado ou executado.

## Execução

`X86SubsetInterpreter::run_loaded_image` recebe uma `LoadedImage`, um endereço de parada e um limite de instruções. Ele zera os registradores, coloca o endereço de entrada virtual em EIP e executa o mesmo decodificador usado pela interface antiga de vetores.

No modo PE32, EIP e os operandos absolutos de memória são endereços virtuais de 32 bits. A busca de cada byte de instrução exige permissão X; a leitura de dados exige R; a gravação exige W. Todos os acessos passam por `VirtualMemory32`, que verifica região, limites e permissões antes de tocar os bytes da imagem.

O endereço de parada é um contrato explícito de cada cenário do laboratório: quando EIP chega a esse endereço, a execução termina com sucesso antes de tentar buscar outra instrução. A fixture usa esse ponto como saída controlada. Isso evita introduzir stack, chamadas ou `RET`, que não fazem parte do subconjunto atual.

## Fixture e relocação

A fixture tem seções executável `.text`, gravável `.data` e somente leitura `.reloc`. Seu fluxo é:

1. `MOV EAX,[data]` carrega 40.
2. `ADD EAX,2` calcula 42.
3. `MOV [result],EAX` grava o resultado.
4. `CMP EAX,42` e `JNZ` verificam o cálculo; uma divergência entra em um loop limitado pelo cenário.
5. No caminho correto, um salto alcança o endereço de parada informado.

Dois registros `HIGHLOW` relocam os operandos absolutos das instruções `MOV` em `.text` (RVA `0x1001` e `0x100B`). Assim, as bases alternativas usam os endereços virtuais correspondentes de `.data`, em vez de depender da base preferida.

## Reprodução e resultados

Em Apple silicon:

```sh
cmake -S lab -B build/arm64 -DCMAKE_BUILD_TYPE=Release
cmake --build build/arm64 --parallel 4
ctest --test-dir build/arm64 --output-on-failure
build/arm64/pe32_execution_lab --scenario all --max-steps 10000
file build/arm64/pe32_execution_lab
lipo -archs build/arm64/pe32_execution_lab
```

`--scenario` aceita `preferred`, `rebased` ou `all`; o padrão é `all`. `rebased` executa as bases `0x500000` e `0x300000`, além da base preferida `0x400000` quando o cenário é `all`. `--max-steps N` configura o limite separadamente para cada execução; o padrão é 10.000.

A saída mostra base, valor gravado, EAX, EIP, passos e motivo de término. A execução correta termina com `reason=stop-address`, EAX igual a 42 e o valor 42 em `.data` nas três bases. A falha da comparação entra no loop da própria fixture e termina com `reason=execution limit exceeded`.

Saída verificada com o limite padrão:

```text
preferred base=0x00400000 result=42 eax=0x0000002a eip=0x0040101a steps=6 reason=stop-address
rebased-up base=0x00500000 result=42 eax=0x0000002a eip=0x0050101a steps=6 reason=stop-address
rebased-down base=0x00300000 result=42 eax=0x0000002a eip=0x0030101a steps=6 reason=stop-address
```

O CTest mantém os testes anteriores e adiciona a verificação de execução nas três bases, dos operandos relocados e dos erros de busca sem X, escrita em seção somente leitura, acesso não mapeado, instrução truncada, opcode desconhecido e limite excedido. No build verificado, os **12/12 testes CTest passaram** e `file`/`lipo` identificaram o executável como **ARM64**.

## Limites

O modo executa somente fixtures originais do projeto e somente as instruções já implementadas no marco 1. Imports continuam sendo endereços resolvidos pelo carregador; não há chamada externa. TLS, APIs Windows, stack, heap, gerenciamento de processo e execução do jogo permanecem fora deste marco. O resultado demonstra a fixture e o modelo implementado, não compatibilidade de executáveis comerciais.
