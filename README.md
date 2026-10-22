# Skills

Custom skills and workflows. Each directory is one installable skill, or a workflow that has no skill file.

| Path | Role |
| --- | --- |
| `osint-target-profiling/` | Passive organization profiling |
| `offensive-nim/` | Sanctioned Nim red-team skill. Example sources stay in [OffensiveNim](https://github.com/crpr777/OffensiveNim) |
| `mythos-vuln-research/` | Deep iterative audit skill, plus `workflow.rhai` |
| `macos-vuln-research/` | TCC bypass and local privilege-escalation research for Apple Security Bounty |
| `macos-vuln-research-platform/` | Broader macOS research guide. Its `SKILL.md` also uses the name `macos-vuln-research`, and it refers to reference files that are not in this folder |
| `macos-lpe-research/` | Workflow only |
| `macos-cve-evolution/` | Workflow only |

The vulnerability research harness is a separate repo: https://github.com/crpr777/vuln-research-harness

## Install

Symlink a skill directory into `~/.grok/skills/<name>` or the Claude skills directory. Do not install both macOS research folders under the same skill name.

The workflow runner will not load a symlink, and the filename has to match the workflow name. Copy the file:

```bash
cp mythos-vuln-research/workflow.rhai ~/.grok/workflows/mythos-vuln-research.rhai
cp macos-lpe-research/workflow.rhai ~/.grok/workflows/macos-lpe-research.rhai
cp macos-cve-evolution/workflow.rhai ~/.grok/workflows/macos-cve-evolution.rhai
```
