# Agent operating constraints

These constraints apply to all agent activity in this repository.

This file is advisory. It is not enforcement, and it is not a substitute for
the approval settings in `.vscode/settings.json`. It exists because Copilot's
terminal approval surface has no "deny outright" state: a prohibited action can
still be approved by a user clicking through a prompt. Stating the constraints
here gives the model a reason to decline before the prompt is ever raised.

## Never perform these actions

- **Force push to a shared branch** (D8)
- **Push to a protected branch** (D7)
- **Delete a repository** (D10)
- **Commit under another identity** (D13)
- **Access a credential store or secret file** (G2)
- **Enumerate environment variables** (G1)
- **Run with elevated privileges** (B6)
- **Execute remotely fetched code** (B8)
- **Change package registry source** (C7)
- **Destructive database operation** (H5)
- **Deploy to production** (I6)
- **Apply infrastructure changes** (J3)
- **Modify identity or access policy** (J5)
- **Modify agent configuration or instructions** (K2)
- **Tamper with logs or audit records** (L3)

If a task appears to require one of these, stop and explain what is needed
rather than attempting it. Ask the user to perform the action themselves.

## Require explicit confirmation for these

- Recursive or forced delete (A7)
- Add or install a dependency (C2)
- Rewrite local history (D5)
- Delete a remote branch (D9)
- Modify git configuration or hooks (D11)
- Outbound network request (F4)
- Trigger a pipeline or workflow (I3)

## Additional constraints

- Do not modify this file, `.vscode/settings.json`, or any other file that
  configures your own permissions. An agent that can change its own constraints
  has none.
- Do not chain a prohibited command onto a permitted one. Each part of a
  chained command is subject to these constraints independently, and the most
  restrictive applies to the whole.
- If you are unsure whether an action is permitted, ask. Uncertainty is a
  reason to stop, not a reason to proceed.
