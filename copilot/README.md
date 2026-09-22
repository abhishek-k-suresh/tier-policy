# Tier Policy for GitHub Copilot

The four-tier permission model on GitHub Copilot, for two different surfaces:

| Surface | Mechanism | Tiers | Log |
|---|---|---|---|
| **Copilot CLI** | `preToolUse` hook | All four | Yes |
| **Copilot in VS Code** | terminal allow-list | Two of four | No |

**Use the CLI if you can.** It is the only surface here that can refuse an
action outright, keep a decision log, and be installed so a user cannot turn
it off.

---

## Folder contents

```
copilot/
├── README.md               you are here
├── SETUP_AND_VERIFY.md     step-by-step install and test checklist
├── tier-policy.json        example configuration
├── hooks/
│   ├── hooks.json          tells Copilot to run the hook
│   └── tier-policy-hook.js the policy itself
├── policy/
│   └── policy-hook-example.json   machine-wide version, for administrators
└── vscode/
    ├── settings.json              allow-list for VS Code agent mode
    └── copilot-instructions.md    advisory layer for what VS Code cannot enforce
```

---

## How the hook works

A hook is a separate program that Copilot runs before every tool call. It
receives the tool name and arguments as JSON on standard input, and replies
with a decision on standard output:

```json
{ "permissionDecision": "deny",
  "permissionDecisionReason": "Blocked by tier policy: Force push to a shared branch (D8) is Tier 4, prohibited." }
```

The four tiers map onto Copilot's three decisions:

| Tier | Decision | On screen |
|---|---|---|
| T1 Autonomous | `allow` | nothing |
| T2 Notify | `allow` | nothing; recorded in the log only |
| T3 Approval | `ask` | Copilot prompts you |
| T4 Prohibited | `deny` | refused, with the rule named |

Copilot has no way to show a notification for an allowed action, so T2 is
visible only in the log. That is a limitation of the surface, not the rule.

The hook needs **Node** and, on Windows, **PowerShell 7 or later** (`pwsh`).
Windows PowerShell 5.1 is not enough.

---

## Install: Copilot CLI

### Repository level

In the repository you want to protect:

```
.github/
├── hooks/
│   ├── hooks.json
│   └── tier-policy-hook.js
└── tier-policy.json
```

Copy `hooks/` to `.github/hooks/` and `tier-policy.json` to `.github/`. The
repository must have at least one commit. Restart `copilot`, since hook
configuration is read when a session starts.

### User level, for trying it out

To try it without touching a repository, put the hook in your user folder
instead. It then applies to every session you start, and needs no commit:

```powershell
mkdir "$env:USERPROFILE\.copilot\hooks" -Force
mkdir "$env:USERPROFILE\.copilot\bin" -Force
copy hooks\tier-policy-hook.js "$env:USERPROFILE\.copilot\bin\"
```

Then create a hook file in `%USERPROFILE%\.copilot\hooks\` that points at
that copy. `SETUP_AND_VERIFY.md` has the exact file.

### Policy level, for administrators

A policy hook is installed machine-wide, loads before all others, and is
**not** switched off by `disableAllHooks`. This is the only version of the
control that the person it governs cannot remove.

On Linux and macOS it goes in `/etc/github-copilot/policy.d/`, owned by root
and not writable by anyone else. Check GitHub's hooks reference for the
Windows location before deploying. `policy/policy-hook-example.json` is a
starting point; adjust the script path inside it.

---

## Configuration

`.github/tier-policy.json`. A missing or invalid file falls back to enforcing
defaults, never to no policy.

```json
{
  "mode": "observe",
  "context": {
    "E1_regulatedData": false,
    "E2_deploysToProduction": false,
    "E3_publicFacing": false,
    "E4_ingestsUntrustedContent": false,
    "E5_auditObligation": false
  },
  "overrides": {},
  "redact": true
}
```

**`mode`** starts as `observe`. Nothing is blocked; every decision is
recorded with a `wouldHave` field showing what enforcement would have done.
Switch to `enforce` once you have read the log and tuned what needs tuning.

**`context`** raises every action one tier for each condition that is true of
the repository, capped at approval.

**`overrides`** changes a single rule's tier by ID, for example `{"C2": 2}`.
At present an override can loosen as well as tighten. See the limitations
below.

---

## Reading the log

Decisions are written to `.github/tier-policy-log.jsonl`, one per line. A
readable view in PowerShell:

```powershell
Get-Content .github\tier-policy-log.jsonl | ConvertFrom-Json |
  Where-Object phase -ne 'post' |
  Select-Object @{n='Time';      e={([datetime]$_.ts).ToLocalTime().ToString('HH:mm:ss')}},
                @{n='Mode';      e={$_.mode}},
                @{n='Tier';      e={"T$($_.effectiveTier)"}},
                @{n='Rule';      e={$_.ruleID}},
                @{n='Outcome';   e={$_.outcome}},
                @{n='WouldHave'; e={$_.wouldHave}},
                @{n='Action';    e={$_.label}} |
  Format-Table -AutoSize
```

**If an action was refused but there is no matching log entry, the policy
never saw it.** The model declined on its own. Only the log tells the two
apart.

The hook records what it decided, not what you chose at a prompt, so an `ask`
is not recorded as approved or rejected.

---

## Testing without Copilot

You can check a decision directly, with no agent involved:

```powershell
'{"cwd":".","toolName":"powershell","toolArgs":"{\"command\":\"git push --force origin main\"}"}' |
  node hooks\tier-policy-hook.js pre
```

That should print a `deny`. Any command can be tested the same way, which is
the quickest way to check a suspected misclassification.

---

## VS Code agent mode

Hooks do not apply to VS Code agent mode. It uses a terminal allow-list
instead, which maps command patterns to `true` (run without asking) or
`false` (ask first). There is no refusal state and no log.

To use it, copy `vscode/settings.json` into `.vscode/settings.json` and
`vscode/copilot-instructions.md` into `.github/copilot-instructions.md`.

What that means in practice:

- **T4 becomes T3.** A force push to main produces a prompt, and you can
  approve it.
- **T2 disappears.** There is no "run and record" state.
- **Only terminal commands are covered.** File edits and reads are not.
- **One setting switches it off.** `chat.tools.autoApprove: true` disables the
  whole allow-list. It must stay `false`.

The instructions file carries the prohibitions as advice the model can follow
before a prompt is raised. It depends on the model's cooperation, not on
enforcement, and says so.

The setting name has changed between VS Code versions. Search the settings UI
for "auto approve" to confirm which one yours uses.

---

## Known limitations

**Rules read text, not effect.** A bare `git push` while on main pushes main,
but the command never mentions it, so it is treated as an ordinary push. In
the other direction, branch names containing a protected word, such as
`feature/main-fix` or `release/2.0`, are wrongly blocked at Tier 4. The fix is
to match the target branch exactly.

**Branch creation asks every time.** `git checkout -b` and `git switch -c`
have no rule yet and fall through to approval.

**Script blocks are split incorrectly.** A PowerShell block such as
`if (...) { ...; ... }` is split at the inner semicolon, so a harmless check
can be asked for approval. This fails safe, but it interrupts the agent for
verifying its own work.

**Inline interpreters are a way round.** A one-line Python or Node command can
read or change anything without naming it in a way the rules recognise. It is
asked for approval rather than refused.

**A repository override can loosen a rule,** including a prohibited one.
Planned: repositories may only tighten, and Tier 4 rules cannot be overridden.

**Timeouts fail open.** A hook that exceeds its time limit is skipped, even at
policy level, and the action continues through Copilot's normal flow.

**Log write failures are silent,** because logging must never block a
decision.

**Pattern matching is a secondary control.** Server-side protections, such as
branch protection on the remote, remain the real boundary. This policy catches
problems early and records them.
