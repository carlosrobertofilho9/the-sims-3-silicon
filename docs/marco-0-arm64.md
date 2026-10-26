# Marco 0 — início da pesquisa ARM64

Data da inspeção: 2026-10-26. Alvo: o pacote instalado **The Sims 3 Complete Collection**, versão declarada 1.67.2. A inspeção abaixo leu metadados e cabeçalhos; não iniciou o aplicativo nem alterou a instalação.

## Evidências observadas

- O Mac informa arquitetura ARM64 e macOS 27.0.1.
- O iniciador do pacote é Mach-O x86_64. O pacote identifica Wineskin 2.9.0.6.
- Os arquivos de suporte do Wine identificam Wine 4.18. Os executáveis de host encontrados são x86 e x86_64. Eles não foram executados.
- Foram analisados 11 arquivos PE no diretório `Game/Bin` da instalação base; todos são x86. `TS3W.exe`, `TS3.exe` e `Sims3Launcher.exe` foram verificados separadamente.
- A tabela normal de imports de `TS3W.exe` contém `d3d9.dll` e `d3dx9_31.dll`. Essas são dependências diretas observadas de DirectX 9. Imports adiados e bibliotecas carregadas dinamicamente continuam desconhecidos.
- `codesign --verify --deep --strict` falha com divergência do selo do `Info.plist`. A avaliação de execução do macOS também é rejeitada e indica divergência no diretório de recursos. O relatório da ferramenta traduz essas saídas em categorias estáveis e não as reproduz literalmente.
- A busca local em `DiagnosticReports` não encontrou registros correspondentes aos processos conhecidos do iniciador e do jogo. Essa busca não cobre o log unificado inteiro do macOS.

## Fatos, hipóteses e pendências

**Fatos:** o iniciador x86_64 e os executáveis Windows x86 pertencem a camadas diferentes; o jogo pede diretamente DLLs do DirectX 9; e a validação de assinatura/selo do pacote falha.

**Hipótese:** a divergência de assinatura pode levar o macOS a bloquear o iniciador. Esta inspeção não tentou abrir o pacote, então não confirma que essa seja a única causa da falha observada.

**Verificações pendentes:** verificar a disponibilidade de Rosetta, entender se os componentes Wine x86/x86_64 deste pacote conseguem executar esse PE x86 na versão atual do macOS e correlacionar uma tentativa controlada com um registro de falha sanitizado. A tabela de imports não revela tudo que o programa carrega durante a execução.

## Reprodução

Requer Python 3 padrão no macOS; o diagnóstico não instala pacotes e só executa os utilitários de assinatura do sistema. O caminho é informado pelo operador e nunca copiado ao relatório.

```sh
python3 tools/diagnose.py diagnose \
  --app "/Applications/The Sims 3 Complete Collection.app" \
  --format markdown
```

Para JSON no terminal, use `--format json`. Para salvar em vez de imprimir, acrescente `--output caminho/do/relatorio.json` (ou `.md`). O conteúdo salvo continua sem caminhos absolutos, identificadores, registros brutos ou dados do jogo. Se o pacote não existir, a ferramenta ainda produz um relatório `not_found` e termina com código 2.

Os testes do parser usam arquivos PE sintéticos originais para cobrir um PE x86 válido, dados truncados, caminho/arquivo ausente e uma arquitetura PE desconhecida:

```sh
python3 -m unittest discover -s tests -v
```

## Laboratório de memória sintética

O laboratório C++17 só usa bytes criados em memória e offsets de 32 bits. Ele traduz cada offset em um acesso ao vetor do processo de 64 bits depois de validar alinhamento e limites; a soma de endereços de 32 bits é checada antes de acontecer. Não abre executáveis do jogo, não lê memória de outro processo e não executa instruções x86.

Em Apple silicon, configure, compile e execute assim:

```sh
cmake -S lab -B build/arm64 -DCMAKE_OSX_ARCHITECTURES=arm64
cmake --build build/arm64
./build/arm64/synthetic_memory_lab
file build/arm64/synthetic_memory_lab
ctest --test-dir build/arm64 --output-on-failure
```

A execução imprime `target=ARM64`, `process_bits=64` e `checks=11 passed`. O código também falha na compilação se o alvo não for ARM64. As 11 verificações cobrem escrita/leitura, alinhamento, último valor válido, posições fora dos limites e overflow de endereço.

## Conceitos e limites

- **Compatibilidade:** Wineskin organiza o pacote e Wine fornece interfaces Windows. Uma camada de compatibilidade não converte, por si só, instruções x86 em ARM64.
- **Tradução de instruções:** Rosetta pode traduzir código de host Intel macOS para Apple silicon, quando suportado e instalado. Isso não transforma o jogo Windows de 32 bits em código ARM64, não substitui Wine e ainda precisa ser investigado neste pacote.
- **Recompilação:** produzir uma versão ARM64 a partir do código-fonte do jogo e de uma cadeia de build compatível. Este repositório não tem esse código, e este marco não recompila o jogo.
- **Reimplementação:** criar código novo que reproduza comportamentos escolhidos a partir de especificações e observações. Isso é um projeto distinto, não uma conversão automática nem uma alegação de equivalência ao jogo.

O laboratório demonstra somente uma fronteira de dados: um offset de 32 bits pode endereçar com segurança um vetor dentro de um processo ARM64 quando os limites são verificados. Ele não demonstra compatibilidade, desempenho, tradução de código nem viabilidade de um porte.

## Privacidade e conteúdo

O JSON de baseline registra apenas versão, arquiteturas, nomes de DLL importadas, resumo de assinatura, contagem/categorias de registros e limites do método. O código remove caminhos, identificadores e conteúdo bruto. Nenhum executável, biblioteca, captura, dump, recurso ou dado salvo do jogo foi copiado para o repositório.
