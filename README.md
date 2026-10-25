# The Sims 3 Silicon

**An unofficial community research and preservation project.** Not affiliated with, endorsed by, or sponsored by Electronic Arts or Maxis.

The Sims 3 and related names are trademarks of their respective owners. This repository contains no game files and grants no rights to game content.

## Purpose

This project explores responsible community research into preserving and understanding The Sims 3 on macOS, especially Apple silicon Macs. Topics include memory behavior, ARM64 execution, graphics performance, and the feasibility of Metal-related research.

We share original documentation, measurement methods, and original tools or code. Contributors use their own legally obtained copy where needed. Compatibility, performance improvements, an ARM64 port, and Metal support are not promised.

## Scope and limits

- Do not submit or distribute game binaries, source code, extracted assets, audio, video, textures, fonts, save files, installers, keys, modified executables, or other proprietary game materials.
- Do not submit decompiled or disassembled game code, copied proprietary code, or raw diagnostic captures that may contain game content or personal information.
- This project does not provide or seek ways to bypass DRM, license checks, or other access controls.
- Research must comply with applicable law and relevant agreements. Contributors are responsible for assessing their own work and submissions.
- Share sanitized summaries instead of raw crash reports, memory dumps, traces, or screenshots.
- The project is experimental and offers no compatibility, performance, stability, or support guarantees.

## Investigation roadmap

These are research questions, not promised outcomes.

1. **Establish a baseline:** record repeatable workloads and aggregate memory observations such as resident memory, memory pressure, and swap use.
2. **Study memory behavior:** document methods, results, and limitations without redistributing game code or data.
3. **Investigate ARM64:** document publicly observable architecture and runtime facts; assess original tooling and legally permitted interoperability research. Do not assume a native ARM64 build is possible.
4. **Investigate graphics and Metal:** measure observable behavior and bottlenecks; explore ideas in a separate original test harness with synthetic or openly licensed assets.
5. **Review findings:** validate original tools, report limitations, and update the roadmap based on evidence.

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [IP-POLICY.md](IP-POLICY.md) before participating. [LICENSE-CODE.md](LICENSE-CODE.md) applies only to original source code, not documentation, third-party material, or game content.

## Português

**Projeto comunitário independente de pesquisa e preservação; não oficial e sem vínculo, endosso ou patrocínio da Electronic Arts ou da Maxis.**

O projeto investiga questões de memória, execução ARM64 e gráficos/Metal de The Sims 3 no macOS, especialmente em Macs Apple silicon, sem prometer compatibilidade ou melhorias. O repositório aceita somente documentação, métodos, ferramentas e código originais. Não inclua arquivos do jogo, conteúdo extraído, executáveis modificados, dumps ou capturas brutas. Consulte [CONTRIBUTING.md](CONTRIBUTING.md) e [IP-POLICY.md](IP-POLICY.md).
