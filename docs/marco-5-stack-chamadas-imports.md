# Marco 5 — stack, chamadas e imports sintéticos

O laboratório agora executa uma fixture PE32 própria que chama uma rotina interna e dois imports sintéticos, passa argumentos pela stack e termina com EAX igual a 42 e ESP restaurado. A fixture está em [pe32_calls_fixture.hpp](../lab/tests/pe32_calls_fixture.hpp); não usa executáveis, bibliotecas, APIs ou conteúdo do jogo.

## Stack e interface

O overload `run_loaded_image(image, stop, options, max_steps)` aceita a opção `enable_stack` e um registro de handlers sintéticos. Com a stack ativada, reserva `0x7FF00000–0x7FF0FFFF` (64 KiB) com leitura e escrita, sem execução, e inicializa ESP em `0x7FF10000`. As páginas de guarda de 4096 bytes em `0x7FEFF000–0x7FEFFFFF` e `0x7FF10000–0x7FF10FFF` ficam não mapeadas. A reserva inteira, incluindo as guardas, precisa estar livre antes do início.

O overload anterior continua disponível e inicia todos os registradores em zero, inclusive ESP. O interpretador compartilha o mesmo decodificador para execução por vetor e para PE32 carregado; cada acesso continua passando pelo respectivo adaptador de memória e suas verificações de limites e permissões.

## Instruções acrescentadas

As codificações seguem o [manual Intel® 64 and IA-32](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html), Volume 2; somente as formas abaixo são aceitas neste subconjunto. Prefixos, opcodes e demais formas não implementadas continuam gerando erro.

| Forma | Codificação aceita |
| --- | --- |
| `PUSH r32` / `POP r32` | `50+rd` / `58+rd` |
| `PUSH imm32` | `68 id` |
| `CALL rel32` | `E8 cd` |
| `CALL [disp32]` | `FF 15 id` |
| `RET` / `RET imm16` | `C3` / `C2 iw` |
| `ADD ESP, imm8` | `83 C4 ib`, com imediato de 8 bits com sinal |

`PUSH ESP` empilha o valor anterior de ESP; `POP ESP` carrega o valor removido. Chamadas internas empilham o endereço de retorno e `RET` o remove. Cada instrução `CALL` concluída conta como uma instrução; a execução de um handler importado não adiciona um `RET` convidado separado.

## Imports e convenções

Cada `SyntheticImportHandler` registra endereço virtual, número de argumentos de 32 bits, convenção e uma função original do laboratório. O `CALL [disp32]` lê o destino a partir da IAT, empilha o retorno e, quando há handler registrado para aquele destino, lê os argumentos convidados em ordem declarada e entrega o valor retornado em EAX. Endereços virtuais nunca são convertidos em ponteiros de função do host.

Os argumentos são empilhados da direita para a esquerda conforme as convenções x86 documentadas pela [Microsoft](https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions?view=msvc-170). Em `cdecl`, a fixture remove os dois argumentos com `ADD ESP,8`; em `stdcall`, o handler simula a limpeza feita pelo chamado. O callback recebe somente os argumentos e retorna um inteiro, portanto não pode alterar os outros registradores ou ZF; o retorno muda apenas EAX, enquanto ESP e EIP seguem as regras da chamada.

## Fixture

O fluxo de sucesso é:

1. `CALL rel32` chama uma rotina interna, que retorna 40 em EAX por `MOV` e `RET`.
2. A fixture empilha 2 e 40 e chama por `CALL [disp32]` o import por nome com `cdecl`.
3. Depois de confirmar que ZF foi preservada, limpa os argumentos no chamador.
4. Empilha 0 e 42 e chama por `CALL [disp32]` o import por ordinal com `stdcall`.
5. Depois de confirmar ZF novamente, grava 42 em `.data`, salta sobre o loop de falha e alcança o endereço de parada do cenário. Um resultado divergente entra no loop, limitado por `--max-steps`.

Os três operandos absolutos da fixture — as duas referências à IAT e a gravação em `.data` — recebem relocação `HIGHLOW`. Os imports sintéticos resolvem para endereços de laboratório fixos; o carregador continua sem carregar DLLs ou executar APIs.

## Reprodução e resultados

Em Apple silicon:

```sh
cmake -S lab -B build/arm64 -DCMAKE_BUILD_TYPE=Release
cmake --build build/arm64 --parallel 4
ctest --test-dir build/arm64 --output-on-failure
build/arm64/pe32_calls_lab --scenario all --max-steps 10000
file build/arm64/pe32_calls_lab
lipo -archs build/arm64/pe32_calls_lab
```

`pe32_calls_lab` mantém `--scenario preferred|rebased|all` e `--max-steps N`, com padrão `all` e 10.000 instruções por base. O cenário `rebased` executa `0x500000` e `0x300000`; `all` também executa `0x400000`.

Saída observada:

```text
preferred base=0x00400000 result=42 eax=0x0000002a esp=0x7ff10000 eip=0x0040105a steps=23 imports=2 args=40,2;42,0 registers=preserved reason=stop-address
rebased-up base=0x00500000 result=42 eax=0x0000002a esp=0x7ff10000 eip=0x0050105a steps=23 imports=2 args=40,2;42,0 registers=preserved reason=stop-address
rebased-down base=0x00300000 result=42 eax=0x0000002a esp=0x7ff10000 eip=0x0030105a steps=23 imports=2 args=40,2;42,0 registers=preserved reason=stop-address
```

Os testes também cobrem chamadas aninhadas, `RET imm16`, `PUSH ESP`, `POP ESP`, stack legado sem mapeamento, limites e guardas, permissões da stack, conflito de região, destino de chamada não mapeado e import sem handler. As suítes de loader, execução do Marco 4, interpretador x86 e limites de memória continuam no CTest: **15/15 passaram**; as suítes Python anteriores também passaram (**19/19**). `file` e `lipo -archs` confirmaram o executável novo como **ARM64**.

## Limites

O perfil implementa apenas as formas listadas e duas convenções com argumentos inteiros de 32 bits. A stack é fixa e sintética; não há TLS, DLLs reais, APIs Windows, heap, processo ou execução do jogo. Estes resultados validam apenas a fixture original e a memória simulada do laboratório.
