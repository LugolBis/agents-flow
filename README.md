# agents-flow

`agwo` is a blazingly fast multi-agent runtime built around a simple principle: **security must never depend on LLMs behaving**.
Permissions are enforced at the tool level, not left to the model. Every action is controlled. Every decision is auditable.

One static binary per platform — **Windows 11 ARM64** (`aarch64-pc-windows-msvc`) and **Linux ARM64** (`aarch64-unknown-linux-gnu`) are
first-class targets; x86-64 builds of both work too. No Python, no OpenSSL, no C library to install.

## Getting Started

### Installation

Requirements: Rust ≥ 1.80.

- Install using `cargo` :
  ```bash
  cargo install agwo
  ```

- Compile from source :
  > [!NOTE]
  > On Windows ARM64 : Visual Studio Build Tools with the *ARM64* C++ tools, with `clang` configured in the _PATH_.
  > You need [Git for Windows](https://git-scm.com) (ARM64 or x64) for the Git tools. `.cargo/config.toml` links the MSVC runtime statically.

  ```bash
  git clone https://github.com/LugolBis/agents-flow.git
  cd agents-flow

  cargo build --release          # target/release/agwo[.exe]

  # Linux ARM64 binary from another machine (e.g. to feed the WSL backend)
  rustup target add aarch64-unknown-linux-gnu && cargo build --release --target aarch64-unknown-linux-gnu
  ```

### Usage

```bash
agwo --config ./config verify          # replay 21 real attacks, no LLM, no network (non-zero exit if one succeeds)
agwo permissions                       # agent x capability x tool matrix
agwo doctor                            # platform (native vs emulated), git, WSL, LLM server
agwo llm-check

agwo run "Document the project in ~/workspace/app"            # plan mode (default)
agwo run --mode hierarchical "…"                              # manager delegates to workers
agwo pipeline readme -p path=app       # also: translate -p source=a.md -p dest=a.en.md | summarize | research | inspect

agwo wsl sync --binary target\to\your\linux\agwo --config .\config # sync your current configs into WSL for the `wsl` backend

agwo audit --tail 50 --denials
```

LLM: `deployment.jsonc` (see `config/deployment.example.jsonc`) for any OpenAI-compatible server (LM Studio, vLLM, llama.cpp…), or
`default_llm = "anthropic/<model>"` (`ANTHROPIC_API_KEY`) / `"openai/<model>"` (`OPENAI_API_KEY`).
`function_calling: false` switches to a ReAct text protocol that works with any model.

## Backends

* `local` (default): tools run in-process — Linux, **native Windows**, macOS.
* `wsl`: agent loop on Windows, **all** tools in a WSL2 distro through the Linux build of this binary (`agwo executor --serve`,
  JSON lines over stdin/stdout, config SHA-256 handshake, local *and* remote authorization).
  `agwo wsl sync --binary path/to/linux/agwo` installs binary + config (refuses an x86-64 binary on an ARM64 distro).

## Known gaps / limits

* `browser_fetch` (Playwright) → returns `browser_unavailable`; no JavaScript rendering.
* `python_import_graph` uses a lexical scanner, not `ast` (syntax errors are not reported).
* PDF text via `lopdf` (simple fonts fine; some CID/scanned PDFs yield little text). No PDF OCR. XLSX dates appear as serial numbers. `.doc/.xls/.ppt/.odt` unsupported (as before).
* `unified diff`/similarity use the `similar` crate (Myers), so the ratio can differ slightly from `difflib`.
* Windows Job Object assignment happens right after spawn (tiny window for very short-lived git children).
* `run_tests` and the Windows/ARM64 code paths are **not exercised** by this repository's tests on a real Windows machine (see below).
* The original archive did not contain `config/*.jsonc`, `skills/`, tests or a README: the files in `config/` were written from the schema
  and code. Your own policy files use the same schema and tool `class` paths, but check them with `agwo verify` first.
