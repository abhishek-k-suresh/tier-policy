# Tier Policy

A permission model for AI coding agents, with working implementations for
**Amp** and **GitHub Copilot**.

AI coding agents now create files, run commands, install packages and push
code, largely without a person approving each step. This project catalogues
what an agent can do, sorts each action by how much oversight it needs, and
enforces that decision before the action runs.

One set of rules, two tools, one decision log.

---

## The model in one table

| Tier | Name | What happens | Example |
|---|---|---|---|
| **T1** | Autonomous | Proceeds silently | `git status` |
| **T2** | Notify | Proceeds, and is recorded | deleting a file |
| **T3** | Approval | Waits for a person to agree | `npm install` |
| **T4** | Prohibited | Refused, with no way to approve it | `git push --force` |

Actions are tiered against five questions: can it be undone, how far does the
damage reach, does anything leave our control, does it touch secrets or real
data, and would we notice if it went wrong.

The tier rises automatically in sensitive repositories: regulated data,
production deployment, public-facing code, untrusted content, or an audit
obligation. It never rises into T4 that way. Prohibition is a deliberate
decision, not the sum of risks.

---

## Where to start

| If you use | Go to |
|---|---|
| Amp | [`amp/`](amp/) |
| Copilot CLI or Copilot in VS Code | [`copilot/`](copilot/) |
| Neither yet, or you want the reasoning | [`docs/`](docs/) |

Whichever tool you use, **start in observation mode.** The policy records
what it *would* have done without blocking anything. Read the log after a
week or two, tune the rules that fire too often, then switch enforcement on.

---

## One rule, three places

The same rule behaves differently depending on what the tool can express.
Here is force-pushing to a shared branch (rule D8):

| | Amp | Copilot CLI | Copilot in VS Code |
|---|---|---|---|
| Mechanism | Plugin inside the agent | Hook, a separate program | Settings allow-list |
| Tiers supported | All four | All four | Two of four |
| Force push to main | **Refused** | **Refused** | Prompts, and can be approved |
| Decision log | Yes | Yes | None |
| Can the user turn it off? | Yes | Not if installed as a policy hook | Yes, with one setting |

The expressiveness of a policy is bounded by the weakest place it is enforced.
See [`docs/Coverage_Comparison.md`](docs/Coverage_Comparison.md).

---

## Repository layout

```
tier-policy/
├── README.md                  you are here
├── amp/                       Amp plugin, config and tests
├── copilot/                   Copilot CLI hook and VS Code settings
└── docs/
    ├── Action_Taxonomy.md     all 90 actions, 12 categories, with rationale
    ├── Observations.yaml      what broke during testing, and what changed
    ├── Coverage_Comparison.md Amp vs Copilot CLI vs VS Code, in detail
    └── Adoption_Guide.pdf     should you use it, and how strictly
```

---

## What was learned

`docs/Observations.yaml` records what happened when the policy met real
agents. A few of the findings:

- **Agents chain commands.** One shell call often holds several operations,
  so a harmless command can carry a prohibited one. Each part is now judged
  separately, and the strictest wins.
- **A refusal blocks an attempt, not a goal.** After one denied delete, the
  agent retried a slightly different command twenty seconds later, and the
  file was gone.
- **Agents learn the rules from being refused.** After one refusal the agent
  stopped attempting the action at all, which made the policy look idle while
  it was working.
- **Counting blocked actions is misleading.** The model refuses some things
  before the policy sees them, learns from refusals, and retries variants. So
  "actions prevented" is the wrong measure of whether this works.
- **Pattern matching is a secondary control.** A command that reaches the same
  outcome through different text, such as an inline Python one-liner, is not
  reliably caught. Server-side protections such as branch protection remain
  the real boundary.

---

## Known limitations

- 36 of the 90 catalogued actions are enforced. Some cannot be seen by a
  plugin or hook at all, such as approving a pull request.
- Rules read command text, not effect. A bare `git push` on main is not
  recognised as a push to main, and some branch names containing a protected
  word are wrongly blocked.
- The log lives inside the workspace, where the agent can read it.
- Copilot hooks that time out are skipped rather than failing closed.

Each limitation is stated in more detail in the relevant folder, and several
are pinned by tests that assert the failure, so a fix is noticed rather than
assumed.

---

## Acknowledgements

Thanks to Luke for showing me how to turn the framework into working
guardrails, through Amp plugins and Copilot hooks, and to the team for
testing it and asking the questions that changed the design.

Built during a Work Integrated Learning placement from public standards
(OWASP Top 10 for LLM Applications, NIST AI Risk Management Framework,
ISO/IEC 42001, MITRE ATLAS) and public product documentation. Contains no
organisation-specific configuration or data. 
