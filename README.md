<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=REGEXLAB&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="REGEXLAB"/>

# REGEXLAB

### Test, explain & benchmark regexes + a library of security patterns

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Test+explain++benchmark+regexes++a+library+of+security+patte;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-regexlab.svg?color=6b46c1)](https://pypi.org/project/cognis-regexlab/) [![CI](https://github.com/cognis-digital/regexlab/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/regexlab/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Part of the Cognis Neural Suite.*

</div>

```bash
pip install cognis-regexlab
regexlab scan .            # → prioritized findings in seconds
```


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ regexlab-emit --version
regexlab 1.0.0
```

```console
$ regexlab-emit --help
usage: regexlab [-h] [--version] {explain,test,bench,scan,patterns} ...

Test, explain & benchmark regexes + a library of security patterns. regex
without footguns.

positional arguments:
  {explain,test,bench,scan,patterns}
    explain             break a regex into plain English
    test                run a regex against input
    bench               benchmark a regex
    scan                scan input with the security pattern library
    patterns            list built-in security patterns

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

> Blocks above are real `regexlab` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"findings": [
    {
        "id": "123456",
        "title": "Suspicious Network Activity",
        "description": "Potential malicious activity detected on network 192.168.1.100",
        "severity": "medium",
        "created_at": "2023-02-15T14:30:00Z"
    },
    {
        "id": "789012",
        "title": "Malware Detection",
        "description": "Detected malware 'BadBot' on system 'Windows-10-PC'",
        "severity": "high",
        "created_at": "2023-02-15T14:31:00Z"
    }
]
}
```

<!-- cognis:example:end -->

## Usage — step by step

1. **Install** (Python 3.9+):

   ```bash
   pip install regexlab            # or: pipx install regexlab
   ```

2. **Explain a pattern** in plain English:

   ```bash
   regexlab explain '^(\d{4})-(\d{2})-(\d{2})$'
   ```

3. **Test it against input.** Pass the subject inline with `-t` (or `-i` to read from a file), and set flags with `--flags`:

   ```bash
   regexlab test '\bERROR\b' -t "2026 ERROR boot" --flags i
   ```

4. **Benchmark** a regex to catch catastrophic backtracking:

   ```bash
   regexlab bench '(a+)+$' --iterations 1000
   ```

5. **Scan with the security pattern library** and read the result. Use `--min-severity` to filter and `--format json` for machine-readable output:

   ```bash
   regexlab scan -i app.log --min-severity high --format json -o scan.json
   ```

6. **List built-in patterns** and gate in CI:

   ```bash
   regexlab patterns
   regexlab scan -i app.log --min-severity high   # non-zero exit signals findings
   ```

## Contents

- [Why regexlab?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why regexlab?

Test, explain & benchmark regexes + a library of security patterns — without standing up heavyweight infrastructure.

`regexlab` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Parse Flags
- ✅ Flags To List
- ✅ Detect Redos Risk
- ✅ Explain Pattern
- ✅ Test Pattern
- ✅ Benchmark Pattern
- ✅ Scan Text
- ✅ Match To Dict
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-regexlab
regexlab --version
regexlab scan .                       # scan current project
regexlab scan . --format json         # machine-readable
regexlab scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ regexlab scan .
  [HIGH    ] REG-001  example finding             (./src/app.py)
  [MEDIUM  ] REG-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[input] --> P[regexlab<br/>analyze + score]
  P --> OUT[report]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`regexlab` is interoperable with every popular way of using AI:

- **MCP server** — `regexlab mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `regexlab scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis regexlab** | typical tools |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |
<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`regexlab mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/regexlab.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/regexlab.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/regexlab.git" # uv
pip install cognis-regexlab                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/regexlab:latest --help        # Docker
brew install cognis-digital/tap/regexlab                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/regexlab/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/regexlab` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools


**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `regexlab` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
