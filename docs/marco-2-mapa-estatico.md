# Marco 2 — mapa estático dos executáveis

- Estado da coleta: **complete**.
- REA: 6.8.0; Node.js: 24.22.1.
- Escopo: três executáveis PE na pasta Game/Bin; nenhum foi executado e nenhum recurso foi extraído.
- Método: REA 6.8.0 para imports, TLS e load config; parser Python independente para cabeçalhos PE.

## Identidade e estabilidade

| Executável | Bytes | Arquitetura | SHA-256 | Identidade estável | Estado |
|---|---:|---|---|---|---|
| TS3.exe | 30016 | x86 | a9b4578c9fad431b47d832d98d25025df481f3c22dfcba068565bb0c9351baf9 | stable | complete |
| TS3W.exe | 14514496 | x86 | 8ead50f94f60cc2b5160788c8a5573d2dfc0551ab7f3cf994a8833ecfe78d73d | stable | complete |
| Sims3Launcher.exe | 28992 | x86 | 9e7f99b010bf7f305c7c59a83cac31f81ab2ca352fba595c35c71177b03529b1 | stable | complete |

## Síntese

- Imports normais: 785 funções, sendo 747 por nome e 38 por ordinal; imports adiados: 0.
- Diretório TLS encontrado em: TS3W.exe. Callbacks não nulos encontrados: 0.
- Os três executáveis usam base preferida `0x400000`; os três não têm diretório de relocação e têm o sinalizador COFF de relocações removidas.
- Os diretórios PE observados pelo REA coincidem com a leitura independente dos cabeçalhos nos três arquivos.

## Cabeçalhos PE — leitura independente

### TS3.exe

- Ponto de entrada: RVA `0x194f` (endereço preferido `0x40194f`).
- Base da imagem: `0x400000`; formato pe32 / 32 bits / x86.
- Alinhamento: seção `4096`, arquivo `512`; tamanho de imagem declarado `32768` bytes.
- Relocações: `no_directory_stripped_flag_set`; diretório presente=false, RVA `0x0`, tamanho `0`, sinalizador COFF de relocações removidas=true. O parser não decodifica nem aplica entradas.
- Diretório TLS nos cabeçalhos: presente=false, RVA `0x0`, tamanho `0`.
- Conferência REA × cabeçalho independente (imports normal/adiado e TLS): `match`.

- Cabeçalho: record local `peh_661a4c32ebf4f3d9`; fonte: [parser PE independente](../tools/static_map.py), vinculado ao SHA-256 acima.

| Seção | RVA | Bytes virtuais | Offset no arquivo | Bytes brutos | R | W | X |
|---|---:|---:|---:|---:|:---:|:---:|:---:|
| .text | `0x1000` | 3782 | `0x400` | 4096 | ✓ | — | ✓ |
| .rdata | `0x2000` | 5904 | `0x1400` | 6144 | ✓ | — | — |
| .data | `0x4000` | 1224 | `0x2c00` | 512 | ✓ | ✓ | — |
| .rsrc | `0x5000` | 11764 | `0x2e00` | 11776 | ✓ | — | — |

### TS3W.exe

- Ponto de entrada: RVA `0xb7fd51` (endereço preferido `0xf7fd51`).
- Base da imagem: `0x400000`; formato pe32 / 32 bits / x86.
- Alinhamento: seção `4096`, arquivo `4096`; tamanho de imagem declarado `15052800` bytes.
- Relocações: `no_directory_stripped_flag_set`; diretório presente=false, RVA `0x0`, tamanho `0`, sinalizador COFF de relocações removidas=true. O parser não decodifica nem aplica entradas.
- Diretório TLS nos cabeçalhos: presente=true, RVA `0xd426bc`, tamanho `24`.
- Conferência REA × cabeçalho independente (imports normal/adiado e TLS): `match`.

- Cabeçalho: record local `peh_8226e56ce0b70538`; fonte: [parser PE independente](../tools/static_map.py), vinculado ao SHA-256 acima.

| Seção | RVA | Bytes virtuais | Offset no arquivo | Bytes brutos | R | W | X |
|---|---:|---:|---:|---:|:---:|:---:|:---:|
| .text | `0x1000` | 12141393 | `0x1000` | 12144640 | ✓ | — | ✓ |
| .rdata | `0xb96000` | 1770633 | `0xb96000` | 1773568 | ✓ | — | — |
| .data | `0xd47000` | 975748 | `0xd47000` | 434176 | ✓ | ✓ | — |
| .tls | `0xe36000` | 9 | `0xdb1000` | 4096 | ✓ | ✓ | — |
| .rsrc | `0xe37000` | 144488 | `0xdb2000` | 147456 | ✓ | — | — |

### Sims3Launcher.exe

- Ponto de entrada: RVA `0x1751` (endereço preferido `0x401751`).
- Base da imagem: `0x400000`; formato pe32 / 32 bits / x86.
- Alinhamento: seção `4096`, arquivo `512`; tamanho de imagem declarado `32768` bytes.
- Relocações: `no_directory_stripped_flag_set`; diretório presente=false, RVA `0x0`, tamanho `0`, sinalizador COFF de relocações removidas=true. O parser não decodifica nem aplica entradas.
- Diretório TLS nos cabeçalhos: presente=false, RVA `0x0`, tamanho `0`.
- Conferência REA × cabeçalho independente (imports normal/adiado e TLS): `match`.

- Cabeçalho: record local `peh_e83ef2b9abc759f0`; fonte: [parser PE independente](../tools/static_map.py), vinculado ao SHA-256 acima.

| Seção | RVA | Bytes virtuais | Offset no arquivo | Bytes brutos | R | W | X |
|---|---:|---:|---:|---:|:---:|:---:|:---:|
| .text | `0x1000` | 3194 | `0x400` | 3584 | ✓ | — | ✓ |
| .rdata | `0x2000` | 4916 | `0x1200` | 5120 | ✓ | — | — |
| .data | `0x4000` | 1192 | `0x2600` | 512 | ✓ | ✓ | — |
| .rsrc | `0x5000` | 11872 | `0x2800` | 12288 | ✓ | — | — |

## Imports estáticos e dependências

Os nomes abaixo são declarações nas tabelas PE. Eles não demonstram execução nem chamadas alcançáveis.

### TS3.exe

- Tabela normal: 5 DLLs, 66 funções; 66 por nome e 0 por ordinal.
- Tabela adiada: 0 DLLs e 0 funções; cobertura REA `complete`, problemas `0`.

| Grupo funcional | Imports | Módulos declarados | Exemplos |
|---|---:|---|---|
| Gráficos | 0 | — | — |
| Áudio | 0 | — | — |
| Interface e entrada de texto | 1 | `user32.dll` | `MessageBoxW` |
| Memória | 0 | — | — |
| Arquivos e configuração | 6 | `advapi32.dll`, `kernel32.dll` | `GetFileAttributesW`, `RegQueryInfoKeyW`, `RegEnumKeyExW`, `RegOpenKeyExW` |
| Rede | 0 | — | — |
| Concorrência e temporização | 7 | `kernel32.dll` | `CreateProcessW`, `WaitForSingleObject`, `GetCurrentThreadId`, `TerminateProcess` |
| Biblioteca C/C++ | 42 | `msvcp80.dll`, `msvcr80.dll` | `exit`, `_wcmdln`, `_initterm`, `_initterm_e` |
| Outras APIs de sistema | 10 | `kernel32.dll` | `GetModuleFileNameW`, `GetSystemTimeAsFileTime`, `GetTickCount`, `QueryPerformanceCounter` |

DLLs e funções completas por nome/ordinal estão no JSON sanitizado; a captura REA completa permanece em `diagnostics/raw/`.

### TS3W.exe

- Tabela normal: 24 DLLs, 665 funções; 627 por nome e 38 por ordinal.
- Tabela adiada: 0 DLLs e 0 funções; cobertura REA `complete`, problemas `0`.

| Grupo funcional | Imports | Módulos declarados | Exemplos |
|---|---:|---|---|
| Gráficos | 12 | `d3d9.dll`, `d3dx9_31.dll`, `ddraw.dll`, `gdi32.dll` | `Direct3DCreate9`, `D3DXGetShaderSize`, `D3DXFillVolumeTexture`, `DirectDrawCreateEx` |
| Áudio | 2 | `dsound.dll` | `ordinal:1`, `ordinal:9` |
| Interface e entrada de texto | 99 | `imm32.dll`, `user32.dll`, `usp10.dll` | `LoadIconA`, `GetTopWindow`, `SetForegroundWindow`, `DialogBoxParamA` |
| Memória | 11 | `kernel32.dll` | `VirtualQuery`, `LocalFree`, `LocalAlloc`, `GlobalFree` |
| Arquivos e configuração | 85 | `advapi32.dll`, `kernel32.dll`, `setupapi.dll`, `shell32.dll`, `version.dll` | `FlushFileBuffers`, `FindCloseChangeNotification`, `FindNextChangeNotification`, `FindFirstChangeNotificationW` |
| Rede | 65 | `iphlpapi.dll`, `kernel32.dll`, `netapi32.dll`, `wininet.dll`, `ws2_32.dll` | `GetAdaptersInfo`, `GetAdaptersAddresses`, `HttpAddRequestHeadersA`, `InternetErrorDlg` |
| Concorrência e temporização | 33 | `kernel32.dll`, `winmm.dll` | `Sleep`, `GetCurrentThreadId`, `CreateEventA`, `TerminateProcess` |
| Biblioteca C/C++ | 232 | `msvcp80.dll`, `msvcr80.dll` | `_CIsin`, `_HUGE`, `modf`, `_get_osfhandle` |
| Outras APIs de sistema | 126 | `dbghelp.dll`, `kernel32.dll`, `ole32.dll`, `oleaut32.dll`, `psapi.dll` | `GetProcAddress`, `GetModuleHandleA`, `GetLocaleInfoW`, `SetLastError` |

DLLs e funções completas por nome/ordinal estão no JSON sanitizado; a captura REA completa permanece em `diagnostics/raw/`.

### Sims3Launcher.exe

- Tabela normal: 4 DLLs, 54 funções; 54 por nome e 0 por ordinal.
- Tabela adiada: 0 DLLs e 0 funções; cobertura REA `complete`, problemas `0`.

| Grupo funcional | Imports | Módulos declarados | Exemplos |
|---|---:|---|---|
| Gráficos | 0 | — | — |
| Áudio | 0 | — | — |
| Interface e entrada de texto | 1 | `user32.dll` | `MessageBoxW` |
| Memória | 0 | — | — |
| Arquivos e configuração | 6 | `advapi32.dll`, `kernel32.dll` | `GetFileAttributesW`, `RegQueryValueExW`, `RegCloseKey`, `RegEnumKeyExW` |
| Rede | 0 | — | — |
| Concorrência e temporização | 6 | `kernel32.dll` | `CreateProcessW`, `TerminateProcess`, `InterlockedCompareExchange`, `Sleep` |
| Biblioteca C/C++ | 32 | `msvcr80.dll` | `_initterm`, `_initterm_e`, `_configthreadlocale`, `__setusermatherr` |
| Outras APIs de sistema | 9 | `kernel32.dll` | `GetSystemTimeAsFileTime`, `GetCurrentProcessId`, `GetTickCount`, `QueryPerformanceCounter` |

DLLs e funções completas por nome/ordinal estão no JSON sanitizado; a captura REA completa permanece em `diagnostics/raw/`.

## TLS e configuração de carregamento — REA

| Executável | TLS | Callbacks encontrados | Load config | Contagem SafeSEH | Evidence ID de REA |
|---|---|---:|---|---:|---|
| TS3.exe | ausente | 0 | presente | 2 | `ev_4b240e172d75a55a4d8cf8bbd88213b14e3ab0a74958535df33a46631b6fcac3` |
| TS3W.exe | presente | 0 | ausente | — | `ev_53a64d628866f86ae6f23112514bae6190279187f05dbfed7b87cc1f83b68768` |
| Sims3Launcher.exe | ausente | 0 | presente | 1 | `ev_de6da24f67b81025d09e03d00da002e0d4d19ef1648c32e9491f534563ba8c2c` |

TLS/load config descrevem estruturas estáticas; não provam que callbacks executem ou que mitigações sejam aplicadas pelo carregador.

## Comparação com o laboratório

| Capacidade | Declarações observadas | Laboratório atual | Lacuna | Fonte no projeto |
|---|---|---|---|---|
| Carregador PE | Cabeçalhos e seções PE32, imports normais, TLS e load config | Não recebe imagens PE nem mapeia seções | Layout de imagem, entrada, imports, relocações, TLS e load config não são implementados | [x86_subset.cpp](../lab/src/x86_subset.cpp), [x86_subset_lab.cpp](../lab/src/x86_subset_lab.cpp) |
| Memória | Imports incluem declarações de APIs de memória e alocação | Vetor sintético de tamanho fixo com leituras/escritas little-endian de 32 bits validadas | Não há espaço virtual de 32 bits, heap, stack, permissões de página ou alocação do sistema | [synthetic_memory.hpp](../lab/include/synthetic_memory.hpp), [x86_subset.cpp](../lab/src/x86_subset.cpp) |
| Gráficos | Imports DirectX 9 e GDI no executável de runtime | Sem modelo de API gráfica ou DirectX | Sem interfaces COM, estado de dispositivo, recursos ou apresentação | [x86_subset.cpp](../lab/src/x86_subset.cpp) |
| Áudio | Imports DirectSound e multimídia no executável de runtime | Sem modelo de API de áudio | Sem dispositivo, buffers, mixer ou efeitos de temporização | [x86_subset.cpp](../lab/src/x86_subset.cpp) |
| Interface | Imports de janelas, métodos de entrada e composição de texto | Sem janela, fila de mensagens, entrada ou modelo de UI | Sem fronteira de interface de plataforma ou event loop | [x86_subset.cpp](../lab/src/x86_subset.cpp) |
| Arquivos e configuração | Imports de arquivos, registro, shell e versão | Apenas buffers sintéticos de código/dados e saída CLI | Sem modelo de sistema de arquivos, registro ou resolução de recursos | [x86_subset.cpp](../lab/src/x86_subset.cpp), [x86_subset_lab.cpp](../lab/src/x86_subset_lab.cpp) |
| Rede | Imports de Internet, sockets, adaptadores e gerenciamento de rede | Sem modelo de API de rede | Sem sockets, DNS, HTTP ou ciclo de vida de rede | [x86_subset.cpp](../lab/src/x86_subset.cpp) |
| Concorrência | Declarações de threads, espera, sincronização e temporizadores quando presentes | Um único loop sequencial do interpretador | Sem threads, processos, objetos de sincronização ou escalonamento | [x86_subset.cpp](../lab/src/x86_subset.cpp), [x86_subset_lab.cpp](../lab/src/x86_subset_lab.cpp) |
| Bibliotecas C/C++ | Imports das DLLs de runtime MSVC 8 nos três executáveis | C++17 é a linguagem da implementação anfitriã | Sem emulação da ABI Visual C++ de 32 bits ou do runtime alvo | [CMakeLists.txt](../lab/CMakeLists.txt), [x86_subset.cpp](../lab/src/x86_subset.cpp) |
| Semântica de instruções | O uso de instruções não foi medido neste mapa estático | Subconjunto limitado escrito à mão e flag ZF | Ainda não há evidência de quais formas o jogo executa ou de quanto código o subconjunto cobre | [x86_subset.hpp](../lab/include/x86_subset.hpp), [marco-1-x86-subset.md](marco-1-x86-subset.md) |

## Evidências REA

- **TS3.exe** — SHA-256 `a9b4578c9fad431b47d832d98d25025df481f3c22dfcba068565bb0c9351baf9`.
  - Cabeçalhos PE lidos pelo coletor: `peh_661a4c32ebf4f3d9`.
  - imports: `ev_abcdeadca70ae5cd657c6987ff2a66fb813ceea32bf8df54b5d84bf31768d4e1`.
  - TLS/load config: `ev_4b240e172d75a55a4d8cf8bbd88213b14e3ab0a74958535df33a46631b6fcac3`.
- **TS3W.exe** — SHA-256 `8ead50f94f60cc2b5160788c8a5573d2dfc0551ab7f3cf994a8833ecfe78d73d`.
  - Cabeçalhos PE lidos pelo coletor: `peh_8226e56ce0b70538`.
  - imports: `ev_913a585e39a441bd0075dcfc0822fed627ec0e4e01322d0224e9d81cad0a795b`.
  - TLS/load config: `ev_53a64d628866f86ae6f23112514bae6190279187f05dbfed7b87cc1f83b68768`.
- **Sims3Launcher.exe** — SHA-256 `9e7f99b010bf7f305c7c59a83cac31f81ab2ca352fba595c35c71177b03529b1`.
  - Cabeçalhos PE lidos pelo coletor: `peh_e83ef2b9abc759f0`.
  - imports: `ev_4f0353a4419db65ee820d38fd28f43b5b97b9b86be9e70b8d64b519543b62298`.
  - TLS/load config: `ev_de6da24f67b81025d09e03d00da002e0d4d19ef1648c32e9491f534563ba8c2c`.

## Reprodução

Com o REA CLI 6.8.0 e Node 24.22.1 disponíveis localmente, o coletor recebe o pacote `.app`, executa as duas consultas por executável e atualiza os dois relatórios:

```sh
python3 tools/static_map.py --app "$SIMS3_APP" --rea-cli "$REA_CLI" --node "$NODE_24"
```

Os argumentos podem apontar para qualquer instalação local; o JSON e o Markdown não repetem esses caminhos. Os registros REA completos são gravados apenas em `diagnostics/raw/`.

## Limitações

- Imports estáticos não provam que uma API seja chamada, alcançável, resolvida ou usada em execução.
- Os metadados de carregamento não mostram execução de callbacks, chamadas dinâmicas a LoadLibrary, imports vinculados, exports encaminhados nem a tabela IAT carregada.
- Este marco não executa bytes do jogo, decodifica instruções do jogo nem mede cobertura; continua desconhecido quais instruções o jogo usa.
- As categorias de dependência são classificações do analista a partir dos nomes de DLLs e APIs; não descrevem comportamento em execução.
- Os registros REA completos ficam em diagnostics/raw/, pasta excluída do Git.
- REA: A ausência do diretório TLS ou load config significa que essa tabela não foi encontrada; não prova que callbacks ou mitigações não sejam registrados por outro mecanismo.
- REA: Snapshots de imports vinculados, a IAT carregada e a resolução de exports encaminhados em outras DLLs não foram observados.
- REA: Metadados CHPE e ponteiros de relocação dinâmica são endereços virtuais brutos; o alvo da tabela não é derivado nem decodificado.
- REA: Indicações como instrumentação CFG são inferidas dos bits GuardFlags, não de observação das instruções instrumentadas.
- REA: Campos load config posteriores a GuardXFGCheckFunctionPointer não são lidos por esta versão do REA.
- REA: A lista reproduz os diretórios PE de imports e imports adiados; não confirma que um import esteja vinculado, encaminhado ou alcançável em execução.
- REA: A tabela e a contagem SafeSEH são reportadas apenas para PE32; campos homônimos em estruturas PE32+ não são uma tabela SafeSEH.
- REA: Os campos TLS e load config reproduzem diretórios do PE; não provam que um callback rode ou que o carregador aplique uma mitigação.

## Próximo objetivo: Marco 3 — abrir o launcher original

O objetivo prático é fazer aparecer a janela do launcher original do The Sims 3. O experimento com carregador PE sintético pode continuar como trabalho de laboratório, mas não responde a essa pergunta nem é critério para concluir este marco.

A primeira tentativa controlada de abrir o aplicativo instalado foi recusada pelo macOS antes de uma janela aparecer. O diagnóstico local confirmou que a assinatura do pacote está inválida e que o macOS rejeita sua execução; o Rosetta está instalado. Ainda não observamos o Wine nem o launcher Windows funcionando. O registro e os próximos passos estão em [Marco 3 — abrir o launcher original](marco-3-launcher.md).
