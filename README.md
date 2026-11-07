# agent-audit

What did your coding agents actually do?

```bash
npx agent-audit
```

One command reads the session logs Claude Code and Codex already keep on your machine, and reports the calls you'd want to know about:

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
  ! Credential files read                14 in 9 sessions
  ! Your email sent to a site            2 in 1 session
  ✓ Local data sent out                  none
  · Pushes to a git remote               61 in 22 sessions
  ────────────────────────────────────────────────────────────────
  Reached 58 hosts. Most often: github.com (210), npmjs.org (96), pypi.org (40) …
```

*(Illustrative output.)*

It's read-only. It makes no network calls, needs no account and installs no hooks. Nothing leaves your machine.

## What it looks for

| Finding | Examples |
|---|---|
| Catastrophic commands | `rm -rf` on `/`, `~` or `.`, `mkfs`, raw disk writes |
| Destructive commands | force-push, `DROP TABLE` / `TRUNCATE` / `DELETE` without `WHERE`, `curl … \| sh`, a recursive delete outside the project |
| Live secrets in tool calls | an API key or token passed in a command or tool input |
| Credential files read | `.env`, SSH keys, `~/.aws/credentials`, `.npmrc`, keychain reads |
| Local data sent out | `curl -d @file`, uploads, `scp` / `rsync` to a remote |
| Your email sent to a site | your git email in a User-Agent, From header or contact field |
| Sensitive files changed | shell startup files, SSH config, CI workflows, git hooks |
| Sessions with no approval prompts | Claude Code bypass mode, Codex never-ask with a full-access sandbox |

The destructive and catastrophic rules are the same open rules [Agentic Control Plane](https://agenticcontrolplane.com) enforces before a call runs. They're vendored from [acp-install](https://github.com/agentic-control-plane/acp-install). A finding here is a call that check would have held for your approval.

It skips text that's only written or described, not run. That covers a `curl | sh` inside an issue body, a heredoc writing a test file, or a commit message. Placeholder keys like `sk-test-xxxx` aren't reported.

## Options

```text
--days N         look back N days (default 30)
--harness NAME   claude or codex (repeatable)
--email ADDR     also flag this address in outbound headers (git user.email is automatic)
--html FILE      write a shareable HTML report
--json           print the summary as JSON
--examples N     examples per finding (default 3)
--raw            show examples unredacted (local only; don't screenshot)
```

## Privacy

- Examples are redacted by default. Keys and tokens become `[GitHub token]`, email addresses become `[email]`, and your home path becomes `~`.
- The report is safe to screenshot. The HTML export is always redacted.
- `--raw` prints full commands to your own terminal only.

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
