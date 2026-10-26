# Project agent notes

## Reverse engineering with REA

- REA (Reverse Engineer Anything) 6.8.0 is registered as a user-level Codex MCP server, and its `reverse-engineer-anything` skill is installed for this account.
- The REA server uses Node.js 24.22.1 through a server-specific `PATH`; this keeps the project's other Node.js setup unchanged. Restart Codex before expecting REA tools to appear in a session.
- Use REA for questions that depend on the installed Sims 3 package, native binaries, decompilation, or requested runtime evidence. Use ordinary repository tools for analysis of this source repository.
- REA is installed without a native analysis engine. Deep native disassembly still needs a configured provider such as Ghidra, Hopper, or IDA.
- Follow [IP-POLICY.md](IP-POLICY.md): inspect only the user's own legally obtained copy; keep proprietary binaries, decompiled/disassembled code, assets, and raw captures out of this repository; share sanitized observations and original code only.
