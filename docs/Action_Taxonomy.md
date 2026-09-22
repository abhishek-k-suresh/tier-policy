# Agentic Coding Assistant: Action Taxonomy

## Purpose of this document

This is an enumeration of the actions an agentic AI coding assistant can perform within a software development environment, with a proposed permission tier for each. It is the foundation for a governance framework.

## Permission tiers

Tiers run in increasing order of restriction.

| Tier | Name | Meaning |
|---|---|---|
| **T1** | Autonomous | Agent proceeds without notification. |
| **T2** | Notify | Agent proceeds, but the action is logged and surfaced for review. |
| **T3** | Approval required | Agent haults until a human explicitly approves. |
| **T4** | Prohibited | No approval path exists. The action is denied outright. |

**T1 to T3 are quantitative judgements** about how much oversight an action warrants in a given context. **T4 is a categorical judgement** that no legitimate need for an agent to perform the action exists at all, which is why it has no approval path.

## Tiering criteria

Each action is assigned a tier by applying five criteria consistently. The dominant criterion is noted in the rationale column.

| Criterion | Question |
|---|---|
| **Reversibility** | Can a human undo this in seconds, or is it permanent? |
| **Blast radius** | Does the effect stay in the agent's workspace, reach shared code, or reach production? |
| **Trust boundary** | Does anything leave organisational control, or does untrusted content enter? |
| **Sensitivity** | Does it touch credentials, personal data, or regulated systems? |
| **Detectability** | If it goes wrong, would anyone notice, and how quickly? |

## Contextual escalation

Base tiers assume an ordinary internal repository: real code, nothing regulated, no production deployment. Most repositories are not that, so a single fixed table would be either too permissive for sensitive environments or too restrictive for trivial ones. Escalation adjusts for where the agent is working.

An action is raised **one tier** for each of the following conditions that applies to the repository:

| ID | Condition | Why it matters |
|---|---|---|
| **E1** | Handles personal, financial, or otherwise regulated data | Consequences of error extend to customers and regulators |
| **E2** | Deploys to production | Errors reach live systems |
| **E3** | Public-facing or open source | Errors are externally visible and exploitable |
| **E4** | Ingests untrusted third-party content | Prompt injection pathway; agent instructions can no longer be assumed trustworthy |
| **E5** | Subject to a specific audit or compliance obligation | Evidentiary and attribution requirements are stricter |

**Rules governing escalation:**

- Modifiers are cumulative, and **escalation caps at T3**.
- **T4 is assigned by design only and is never reached through escalation.** A categorical prohibition cannot be arrived at by accumulating quantitative risk. If enough modifiers could push an ordinary action into T4, a sufficiently sensitive repository would forbid reading a file, which is absurd.
- Modifiers raise tiers only. **No modifier can lower a tier below its base.** De-escalation is the mechanism most likely to be abused to disable controls, and the repository described as "just a sandbox" is frequently the one that later becomes load-bearing.

## A. Filesystem and workspace

| ID | Action | Tier | Rationale |
|---|---|---|---|
| A1 | Read file within workspace | T1 | No mutation, contained | 
| A2 | Read file outside workspace | T2 | Blast radius beyond scope; possible data discovery | 
| A3 | Create file within workspace | T1 | Reversible, contained | 
| A4 | Modify file within workspace | T1 | Reversible via version control | 
| A5 | Modify file outside workspace | T3 | Escapes containment; may alter host config | 
| A6 | Delete file within workspace | T2 | Recoverable if committed, not if untracked | 
| A7 | Delete directory or bulk delete | T3 | Low reversibility, high blast radius | 
| A8 | Modify files matched by ignore rules (.gitignore, .env) | T3 | These files are excluded for a reason | 
| A9 | Read or write outside the repository root on the host | T4 | No legitimate need; escapes all containment | 

## B. Code execution

| ID | Action | Tier | Rationale | 
|---|---|---|---|
| B1 | Run unit or integration tests | T1 | Read-only in effect, high value | 
| B2 | Run linters, formatters, static analysis | T1 | Contained, reversible | 
| B3 | Run build or compile | T1 | Contained | 
| B4 | Run project scripts defined in the repository | T2 | Contents may not be known to the user | 
| B5 | Run arbitrary shell command | T3 | Unbounded capability; effectively bypasses every other control | 
| B6 | Run command with elevated privileges (sudo, admin) | T4 | No legitimate agent need | 
| B7 | Start long-running or background process | T2 | Persists beyond the session; detectability concern | 
| B8 | Execute code fetched from an external source | T4 | Untrusted execution; supply chain and injection risk | 

## C. Dependency and package management

| ID | Action | Tier | Rationale | 
|---|---|---|---|
| C1 | Read dependency manifest or lockfile | T1 | Read-only | 
| C2 | Add a new third-party dependency | T3 | Supply chain risk; expands attack surface | 
| C3 | Upgrade dependency to a patch version | T2 | Usually safe, but can break behaviour | 
| C4 | Upgrade dependency to a major version | T3 | Breaking change risk | 
| C5 | Remove a dependency | T2 | Reversible, but may break functionality silently | 
| C6 | Modify lockfile directly | T3 | Bypasses resolution; hard to detect | 
| C7 | Change package registry or source URL | T4 | Classic supply chain attack vector | 
| C8 | Install a global or system-level package | T3 | Affects host beyond the project | 

## D. Version control

| ID | Action | Tier | Rationale | 
|---|---|---|---|
| D1 | Read repository history, diff, blame | T1 | Read-only | 
| D2 | Create local branch | T1 | Fully reversible, contained | 
| D3 | Stage changes | T1 | Reversible | 
| D4 | Commit locally | T1 | Reversible, not yet shared | 
| D5 | Amend or rewrite local commit history | T2 | Reversible but can lose work | 
| D6 | Push to a feature branch | T2 | Leaves local machine; visible to others | 
| D7 | Push to a protected or main branch | T4 | Bypasses review entirely | 
| D8 | Force push to any shared branch | T4 | Destroys history; low reversibility | 
| D9 | Delete a remote branch | T3 | Potential work loss | 
| D10 | Delete a repository | T4 | Irreversible, maximum blast radius | 
| D11 | Modify git config or hooks | T3 | Hooks execute code; can disable controls | 
| D12 | Add or modify a git submodule | T3 | Pulls in external code | 
| D13 | Commit on behalf of another identity | T4 | Attribution integrity; audit trail corruption | 

## E. Code review and collaboration

| ID | Action | Tier | Rationale | 
|---|---|---|---|
| E1 | Read an existing pull request | T1 | Read-only | 
| E2 | Open a pull request | T2 | Consumes reviewer attention; must be attributable | 
| E3 | Comment on a pull request | T2 | Visible to others; reviewer-load concern | 
| E4 | Approve a pull request | T4 | Removes the human control the review exists to provide | 
| E5 | Merge a pull request | T4 | Bypasses the review gate | 
| E6 | Modify pull request settings or required checks | T4 | Disables controls | 
| E7 | Create or modify an issue or ticket | T2 | Low risk, but noise-generating at volume | 
| E8 | Post to team chat or notification channel | T3 | Reaches humans directly; impersonation risk | 

## F. Network and external services

| ID | Action | Tier | Rationale | 
|---|---|---|---|
| F1 | Fetch documentation from an approved allowlist | T1 | Bounded, read-only | 
| F2 | Fetch arbitrary URL | T2 | Untrusted content enters the context (injection pathway) | 
| F3 | Call an internal API | T3 | Depends entirely on the API's own authority | 
| F4 | Call an external third-party API | T3 | Data leaves organisational control | 
| F5 | Send data to any external endpoint | T4 | Exfiltration pathway | 
| F6 | Open an inbound network listener | T4 | No legitimate agent need | 

## G. Secrets and credentials

| ID | Action | Tier | Rationale | 
|---|---|---|---|
| G1 | Read environment variables | T3 | Frequently contain credentials | 
| G2 | Read a credential store, keychain, or vault | T4 | No legitimate need; direct compromise path | 
| G3 | Read a file matching secret patterns (.env, .pem, id_rsa) | T4 | Direct compromise path | 
| G4 | Write a credential into a file | T4 | Creates the leak it should prevent | 
| G5 | Use an existing credential to authenticate | T3 | Acts with borrowed authority | 
| G6 | Create, rotate, or revoke a credential | T4 | Identity and access control boundary | 

## H. Data and databases

| ID | Action | Tier | Rationale | 
|---|---|---|---|
| H1 | Read schema or metadata | T2 | Reveals structure but not content | 
| H2 | Read from a development or seeded database | T2 | Contained if genuinely synthetic | 
| H3 | Read from a database containing real data | T4 | Personal or regulated data exposure | 
| H4 | Write or update records | T3 | Mutation of state outside version control | 
| H5 | Delete records | T4 | Irreversible without backup | 
| H6 | Alter schema, migrate, drop table | T4 | Irreversible, high blast radius | 
| H7 | Generate or modify a migration script (not run it) | T2 | Reviewable artifact rather than an executed change | 

## I. CI/CD and deployment

| ID | Action | Tier | Rationale | 
|---|---|---|---|
| I1 | Read pipeline configuration or logs | T1 | Read-only, though logs may leak secrets | 
| I2 | Modify pipeline configuration | T4 | Pipelines enforce the controls; editing them disables enforcement | 
| I3 | Trigger a pipeline run | T2 | Consumes resources; usually reversible | 
| I4 | Deploy to a development environment | T2 | Contained | 
| I5 | Deploy to staging | T3 | Shared environment; visible to others | 
| I6 | Deploy to production | T4 | Maximum blast radius | 
| I7 | Modify a feature flag or runtime configuration | T3 | Changes production behaviour without a deployment | 
| I8 | Roll back a deployment | T3 | Legitimate in incident response, but must be attributable | 

## J. Infrastructure and cloud

| ID | Action | Tier | Rationale | 
|---|---|---|---|
| J1 | Read infrastructure-as-code definitions | T1 | Read-only | 
| J2 | Modify infrastructure-as-code definitions | T3 | Reviewable, but consequences are large if merged | 
| J3 | Apply infrastructure changes | T4 | Direct, often irreversible, cost and security impact | 
| J4 | Read cloud resource configuration | T3 | Reconnaissance value if compromised | 
| J5 | Modify IAM roles, policies, or permissions | T4 | Privilege escalation pathway | 
| J6 | Create or destroy cloud resources | T4 | Cost and availability impact | 

## K. Agent self-configuration

*This category is the one most often overlooked. An agent that can edit its own permissions has no permissions.*

| ID | Action | Tier | Rationale | 
|---|---|---|---|
| K1 | Read its own instruction or configuration file | T1 | Transparency is desirable | 
| K2 | Modify its own instruction or configuration file | T4 | Self-granting authority; defeats the entire model | 
| K3 | Modify another agent's configuration | T4 | Same, laterally | 
| K4 | Install or enable an additional tool, plugin, or connector | T4 | Silently expands capability beyond what was assessed | 
| K5 | Invoke or spawn a sub-agent | T3 | Delegated authority must not exceed the parent's | 
| K6 | Persist state or memory across sessions | T2 | Injected content in one session can influence later ones | 
| K7 | Change its own model or provider | T3 | Alters behaviour and data handling characteristics | 

## L. Observability and audit

| ID | Action | Tier | Rationale | 
|---|---|---|---|
| L1 | Write to its own activity log | T1 | Required for accountability | 
| L2 | Read audit or activity logs | T2 | May contain sensitive operational detail | 
| L3 | Modify or delete log entries | T4 | Destroys the evidence trail | 
| L4 | Disable, reduce, or reconfigure logging | T4 | Removes detectability, which every other control depends on | 

---

## Second axis: output trust and reviewer load

Permission tiering governs **what an agent may do**. It does not address **whether its output can be relied upon**, which is a separate failure mode raised in practitioner discussion:

> An agent asked to find issues will always find issues. It can review the same pull request repeatedly and produce new findings each time. Leaned on too heavily, it generates work rather than reducing it.

The harm here is not damage but attrition. Reviewers facing a continuous stream of low-confidence findings stop reading carefully, and the real finding is missed. This is structurally identical to approval fatigue in the permission model: a control that fires too often stops functioning as a control.

**Candidate controls, to be developed:**

- Findings carry a confidence signal, and low-confidence output is aggregated rather than raised individually
- A budget on findings per review, forcing prioritisation rather than exhaustive listing
- Suppression of findings previously assessed and dismissed, so repeated runs do not resurface them
- Human verification required before an agent-generated finding creates work for another team
- Measurement of the acceptance rate of agent findings as a health signal, since a falling rate indicates the tool is generating noise

---

