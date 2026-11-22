# agent-audit

What did your coding agents actually do?

Paste this into Claude Code or Codex:

```text
Run `npx agent-audit` and walk me through what it found.
```

Or run it yourself:

```bash
npx agent-audit
```

It reads the session logs Claude Code and Codex already keep on your machine, and reports the calls you'd want to know about:

```text
  What your coding agents did in the last 30 days
  Claude Code 48 sessions · Codex 6 sessions · 4,120 tool calls · 2,980 shell commands · $412 spent
  ────────────────────────────────────────────────────────────────
  ✓ Catastrophic commands                none
  ✗ Destructive commands                 3 in 3 sessions
      2026-11-02 Claude Code: force-pushes over shared git history
        git push --force origin main
  ✗ Live secrets in tool calls           1 in 1 session
      2026-10-29 Codex: GitHub token
        curl -H "Authorization: token [GitHub token]" https://api.github.com/…
  ! Personal data the model read         6 in 2 sessions
      2026-10-30 Claude Code: card number in tool output
        Visa card ending 8431
  ! Credential files read                14 in 9 sessions
  ! Your email sent to a site            2 in 1 session
  ✓ Local data sent out                  none
  · Pushes to a git remote               61 in 22 sessions
  ────────────────────────────────────────────────────────────────
  Reached 58 hosts. Most often: github.com (210), npmjs.org (96), pypi.org (40) …
```

*(Illustrative output.)*

It's read-only. It makes no network calls, needs no account and installs no hooks. Nothing leaves your machine. It has no dependencies and needs Node 18 or later.

No npm? Clone the repo and run `node bin/agent-audit.mjs`. There is no install step.

## What it looks for

| Finding | Examples |
|---|---|
| Catastrophic commands | `rm -rf` on `/`, `~` or `.`, `mkfs`, raw disk writes |
| Destructive commands | force-push, `DROP TABLE` / `TRUNCATE` / `DELETE` without `WHERE`, `curl … \| sh`, a recursive delete outside the project |
| Live secrets in tool calls | an API key or token passed in a command or tool input |
| Personal data the model read | a card number, a US Social Security number or someone else's email address in a prompt or in what a tool returned |
| Credential files read | `.env`, SSH keys, `~/.aws/credentials`, `.npmrc`, keychain reads |
| Local data sent out | `curl -d @file`, uploads, `scp` / `rsync` to a remote |
| Your email sent to a site | your git email in a User-Agent, From header or contact field |
| Sensitive files changed | shell startup files, SSH config and authorized_keys, git hooks, crontab, login items |
| Sessions with no approval prompts | Claude Code bypass mode, Codex never-ask with a full-access sandbox |

The destructive and catastrophic rules are the same open rules [Agentic Control Plane](https://agenticcontrolplane.com) enforces before a call runs. They're vendored from [acp-install](https://github.com/agentic-control-plane/acp-install). A finding here is a call that check would have held for your approval.

It skips text that's only written, searched for or described, not run. That covers a `curl | sh` inside an issue body, a `grep` for `git push --force`, a heredoc writing a test file, or a commit message. A heredoc fed to a shell or a SQL client is still checked. Placeholder keys like `sk-test-xxxx` aren't reported.

Personal data is counted once per distinct value, however many times the model read it. The rules lean toward missing something over flagging something that isn't personal:

- Not counted as someone's email: your own git email, role addresses like `support@` and `noreply@`, authors in a git log or a package manifest, ssh logins, and placeholder domains like `example.com`.
- A card number needs a real brand prefix, the right length and a valid checksum. Written without spaces, it also needs a word like "card" or "visa" nearby. Test cards published by payment providers aren't counted.
- A Social Security number is counted only when written with dashes and a nearby word says what it is.
- Phone numbers and street addresses aren't detected.

## Running it from an agent

When a coding agent runs the audit, the agent is the reader. Inside Claude Code the report ends with a few plain notes for it: what to lead with, that the commands shown already ran and shouldn't be run again, and that the examples are redacted on purpose. Pass `--agent` to get the same notes anywhere else.

The agent only ever sees the redacted report. Personal data is shown as `d***@gmail.com`, `Visa card ending 8431` or `***-**-****`, with or without `--raw`.

## Options

```text
--days N         look back N days (default 30)
--harness NAME   claude or codex (repeatable)
--email ADDR     also flag this address in outbound headers (git user.email is automatic)
--html FILE      write a shareable HTML report
--json           print the summary as JSON
--examples N     examples per finding (default 3)
--raw            show examples unredacted (local only; don't screenshot)
--agent          add short notes for a coding agent relaying the report
```

## Privacy

- Examples are redacted by default, and the redaction errs toward hiding too much:
  - Known key shapes become labels like `[GitHub token]`.
  - Passwords in `-u`, `-p`, `--password` and URL userinfo, `NAME_TOKEN=`-style values, and long opaque strings become `[redacted]`.
  - Email addresses become `[email]`, usernames become `[user]`, and home paths become `~`.
  - Intranet and `.local` hostnames are never listed.
- The HTML export is always redacted.
- `--raw` prints full commands to your own terminal only. If an agent runs it, those commands go to the model, so leave it off there.
- Personal data is never printed in full, even with `--raw`.
- Redaction is pattern-based, so glance over a report before you post it.

## Coverage

| Harness | Where it reads | Status |
|---|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` | covered, including subagents |
| Codex CLI | `~/.codex/sessions/**/*.jsonl` | covered: shell, exec code mode, apply_patch |
| OpenCode | `~/.local/share/opencode/opencode.db` | not yet (SQLite) |
| Cursor, Copilot, Gemini CLI | — | not yet |

The session formats aren't documented by their vendors and can change. If a harness update breaks parsing, please open an issue.

## Next step

This shows what already happened. To be asked before the next force-push, `DROP TABLE` or `curl | sh` runs, with the same rules in every harness, see [Agentic Control Plane](https://agenticcontrolplane.com/getting-started).

MIT licensed.
