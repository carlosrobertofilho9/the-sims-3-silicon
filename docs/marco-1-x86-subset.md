# Marco 1 — interpretador x86 mínimo em ARM64

O alvo continua sendo o aplicativo local identificado no Marco 0, mas este marco executa apenas quatro sequências de bytes originais guardadas no projeto. O interpretador não carrega PE, não lê a memória do jogo, não chama APIs do Windows e não executa nenhum conteúdo do aplicativo.

## Interface e execução

```sh
cmake -S lab -B build/arm64 -DCMAKE_OSX_ARCHITECTURES=arm64
cmake --build build/arm64
./build/arm64/x86_subset_lab --program all --max-steps 10000
file build/arm64/x86_subset_lab
ctest --test-dir build/arm64 --output-on-failure
```

A interface aceita `--program arithmetic|memory|branch|loop|all`, com padrão `all`. `--max-steps N` limita cada programa separadamente; o valor padrão é 10.000 e o máximo aceito também é 10.000. A saída mostra resultado, estado, EIP, flag ZF e quantidade de instruções concluídas. O binário imprime seu alvo ARM64 e tamanho de ponteiro, e `file` permite confirmar o formato nativo.

## Subconjunto e semântica

Os bytes seguem os formatos documentados no [Intel® 64 and IA-32 Architectures Software Developer’s Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html), Volume 2:

| Forma | Codificação suportada |
| --- | --- |
| `MOV r32, imm32` | `B8+rd id` |
| `MOV EAX, [endereço]` | `A1 moffs32` |
| `MOV [endereço], EAX` | `A3 moffs32` |
| `ADD EAX, imm32` | `05 id` |
| `SUB EAX, imm32` | `2D id` |
| `CMP EAX, imm32` | `3D id` |
| `JZ rel8` | `74 cb` |
| `JNZ rel8` | `75 cb` |
| `JMP rel8` | `EB cb` |

Os oito registradores são EAX, ECX, EDX, EBX, ESP, EBP, ESI e EDI, todos com 32 bits. A aritmética não sinalizada de ADD/SUB tem wraparound módulo 2³². A única flag modelada é ZF: ADD e SUB a atualizam pelo resultado; CMP compara EAX ao imediato sem alterar EAX; MOV e desvios preservam ZF. CF, OF, SF, PF e AF não são modeladas.

O EIP é um deslocamento de bytes na área de código. `rel8` é interpretado como deslocamento com sinal relativo ao byte seguinte à instrução. Um destino igual ao tamanho do programa encerra normalmente; destino negativo ou maior que o fim dá erro. Chegar exatamente ao fim também é término normal. Instrução incompleta, endereço de dados inválido, prefixo/opcode não suportado ou limite de passos excedido produzem estado final com erro.

Código é um vetor separado da memória de dados sintética. Os operandos `moffs32` são offsets de 32 bits nessa memória de dados; leituras e escritas de 32 bits seguem little-endian, aceitam desalinhamento e validam os limites antes de acessar. Não há acesso à memória do processo anfitrião por endereço fornecido pelo programa.

## Programas embutidos

- `arithmetic`: produz 42 em 4 instruções, mantém EBX e termina com ZF=1.
- `memory`: copia `0x12345678` entre offsets desalinhados em 2 instruções e mostra o valor decimal `305419896`.
- `branch`: termina com EAX=42 e EBX=1 após 10 instruções; exercita JZ tomado, JNZ não tomado e tomado, e JMP relativo positivo.
- `loop`: decrementa EAX de 10 a 0 em 21 instruções com JNZ negativo e termina com ZF=1.
- `all`: roda esses quatro programas em processos lógicos separados, cada um com registradores, código e dados reiniciados.

Os 46 testes do interpretador também verificam os oito destinos MOV, preservação de registradores e ZF, wraparound, acesso desalinhado little-endian, limite da memória, saltos positivos/negativos, destino igual ao fim, opcode/prefixo não suportado, imediato truncado, endereço inválido e loop limitado. O CTest mantém as 11 verificações de limite do Marco 0 e inclui mais quatro verificações little-endian.

## Diagnóstico `.ips` corrigido

O leitor do diagnóstico agora aceita objeto JSON único ou dois objetos JSON sequenciais, inclusive quando o segundo objeto está formatado em várias linhas. Ele compara localmente `bundleID`/nome de processo para correlacionar o app e classifica falhas por campos estruturados `exception` e `termination`. Para a instalação atual, a reanálise local encontrou nove registros compatíveis; os campos de término indicam falhas de assinatura/código. O baseline JSON registra somente a contagem, categoria e escopo. Campos de identificação usados na comparação, caminhos, datas dos registros, nomes dos processos e conteúdo bruto não entram no relatório.

Registros ilegíveis identificáveis pelo nome de processo são contados como `unreadable_record`, sem imprimir conteúdo ou nome de arquivo. Testes sintéticos cobrem JSON único, cabeçalho/corpo, corpo multilinha, arquivo ilegível e sanitização.

## Escopo

Este exercício traduz a semântica de algumas instruções x86 para operações C++ executadas em ARM64. Ele não emite código ARM, não é um JIT, não é um emulador completo de CPU e não prova que instruções ou binários do jogo possam ser carregados. Decodificação PE, APIs Windows, gráficos e execução do jogo continuam fora do marco.
