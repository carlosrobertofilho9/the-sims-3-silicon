# Experimento do laboratório — carregador PE32 em memória simulada

**Escopo deste experimento:** carregamento sem execução automática do ponto de entrada.

Este experimento acrescenta um carregador C++17 para fixtures PE32 x86 originais, uma memória virtual simulada de 32 bits e o comando `pe32_loader_lab`. Os bytes da fixture são montados pelo código em [pe32_fixture.hpp](../lab/tests/pe32_fixture.hpp); nenhum executável ou recurso do jogo foi usado.

## O que o carregador cobre

- Lê cabeçalhos PE32, diretórios, seções, intervalos de arquivo e permissões a partir dos campos little-endian definidos pela [especificação PE da Microsoft](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
- Aceita x86/I386 com `SectionAlignment` de 4096 bytes, `FileAlignment` de 512 a 4096 bytes e imagem de até 64 MiB.
- Mapeia cabeçalhos e seções em regiões próprias, copia os bytes presentes no arquivo e mantém zerado o restante da extensão virtual.
- Usa a base preferida quando nenhuma base é passada. Ao carregar em outra base, aplica relocação `HIGHLOW` e ignora entradas `ABSOLUTE`; sem relocação ou com o sinalizador de relocação removida, recusa a mudança de base.
- Resolve imports normais por nome e ordinal somente por meio de um registro sintético e escreve os resultados na IAT.
- Oferece leituras, escritas e busca de instrução com checagem de região, limites e permissões. A memória convidada nunca é convertida em ponteiros do host.
- Retorna erros estruturados para arquivos ou cabeçalhos inválidos, overflow, seções sobrepostas, arquitetura não suportada, imports ausentes e relocação não suportada.

TLS, imports adiados e load config são recusados explicitamente. O loader não carrega DLLs nem chama funções do sistema. A execução explícita de uma fixture própria por meio do interpretador está documentada separadamente no [Marco 4](marco-4-execucao-pe32.md).

## Reprodução

Em Apple silicon, configure, compile e execute a suíte assim:

```sh
cmake -S lab -B build/arm64 -DCMAKE_BUILD_TYPE=Release
cmake --build build/arm64 --parallel 4
ctest --test-dir build/arm64 --output-on-failure
python3 -m unittest discover -s tests -v
build/arm64/pe32_loader_lab --scenario all
file build/arm64/pe32_loader_lab
lipo -archs build/arm64/pe32_loader_lab
```

O cenário padrão do comando é `all`; `--scenario preferred` roda apenas a base preferida e `--scenario rebased` roda bases acima e abaixo dela.

## Resultados observados

- CTest: **8/8 passaram**, incluindo os quatro testes anteriores e os testes do loader.
- Python: **19/19 passaram**.
- Arquitetura do executável: **ARM64** (`file` e `lipo -archs`).
- Saída do cenário `all`:

```text
preferred base=0x00400000 entry=0x00401000 relocated=0x00401234 regions=5 imports=2 executed=false
rebased-up base=0x00500000 entry=0x00501000 relocated=0x00501234 regions=5 imports=2 executed=false
rebased-down base=0x00300000 entry=0x00301000 relocated=0x00301234 regions=5 imports=2 executed=false
```

As verificações também cobrem cópia de seções, preenchimento com zeros, IAT para nome e ordinal, símbolo ausente, permissões R/W/X, regiões não mapeadas, acessos que cruzam fronteiras, truncamento, arquitetura incompatível, seções sobrepostas, overflow, tipo de relocação desconhecido e diretórios não suportados.

Para manter os testes anteriores verdes, o coletor do mapa estático agora diferencia mudança de arquivo, identidade REA incompatível e consulta sem digest. Uma consulta indisponível é relatada como coleta parcial, em vez de inconsistência.

## Limites

- É um perfil experimental, não uma implementação geral do carregador do Windows. Apenas PE32 x86, seções de 4096 bytes e imagens de até 64 MiB são aceitos.
- O registro de imports fornece endereços virtuais fixos. Não há carregamento de módulos, resolução de exports encaminhados, API sets, imports vinculados ou chamadas às APIs importadas.
- O carregador não executa automaticamente o ponto de entrada. O Marco 4 conecta uma fixture própria ao interpretador, sem acrescentar TLS, APIs, processo, stack, heap, permissões dinâmicas ou alocador de endereços concorrente.
- Os resultados provam somente o comportamento da fixture sintética e do modelo de memória implementado; não demonstram que executáveis do jogo carreguem nesse perfil.
- A recusa de TLS, imports adiados e load config é intencional neste marco; sua preparação pertence a marcos posteriores.
