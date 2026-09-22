/**
 * Tier Policy v3.0 - a reference implementation of a four-tier permission model
 * for agentic coding assistants.
 *
 *   T1 Autonomous   proceed silently              e.g. read a file, git status
 *   T2 Notify       proceed, log and surface      e.g. delete a file, commit
 *   T3 Approval     block until a human approves  e.g. install a dependency
 *   T4 Prohibited   deny outright, no approval    e.g. force push, read .env
 *
 * Contextual escalation raises an action one tier per applicable modifier,
 * capped at T3. T4 is assigned by design only and is never reached by
 * escalation, because a categorical prohibition cannot be arrived at by
 * accumulating quantitative risk.
 *
 * Configuration: .amp/tier-policy.json (see DEFAULT_CONFIG below).
 * Decision log:  .amp/tier-policy-log.jsonl
 *
 * Changes in this version, each driven by observed testing:
 *   OBS-001  shell commands are segmented and classified individually
 *   OBS-002  the catch-all rule is evaluated last, not by tier order
 *   OBS-003  each rule carries both POSIX and PowerShell patterns
 *   OBS-004  every decision is logged, so the control can be evaluated
 *            independently of the model's own refusals
 *   OBS-005  logging failure is loud rather than silent
 *   OBS-006  file paths are extracted from structured patch payloads, not
 *            only from direct path fields
 * 	 OBS-007  The agent learned the policy from being enforced against
 * 	 OBS-008  Segmentation defeated the rules that depend on composition
 *
 * WIL placement project. Built from public documentation; contains no
 * organisation-specific content.
 */

import type { PluginAPI, ToolCall, ToolCallResult } from '@ampcode/plugin'
import { appendFileSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname } from 'node:path'

export const description = 'Enforces a tiered permission model for agent actions.'

// ===========================================================================
// Types
// ===========================================================================

export type Tier = 1 | 2 | 3 | 4
export type Dialect = 'posix' | 'pwsh'
export type Mode = 'enforce' | 'observe'

export interface Rule {
	/** Taxonomy ID, e.g. "D8". Traceable to the action taxonomy document. */
	id: string
	tier: Tier
	/** Shell-independent statement of what the rule detects. */
	label: string
	/** Pattern for bash / zsh (Linux, macOS, Git Bash on Windows). */
	posix?: RegExp
	/** Pattern for PowerShell 7+ (Windows, and cross-platform pwsh). */
	pwsh?: RegExp
	/** Match on the tool call itself rather than on shell text. */
	tool?: (tool: string, input: Record<string, unknown>) => boolean
}

export interface Config {
	/**
	 * enforce: block and prompt according to tier.
	 * observe: classify and log only; nothing is ever blocked or prompted.
	 *
	 * Observe mode exists because no organisation can switch on a blocking
	 * policy across an existing estate without first knowing what it would
	 * break. Run in observe, read the log, tune, then enforce.
	 */
	mode: Mode
	/** Escalation modifiers. Each true value raises every action one tier. */
	context: Record<string, boolean>
	/**
	 * Per-rule tier overrides, e.g. { "C2": 2 }. Lets a team adopt the
	 * baseline while deliberately relaxing or tightening specific rules,
	 * so deviation is explicit and auditable rather than requiring a fork.
	 */
	overrides: Record<string, Tier>
	/** Redact credential-shaped substrings from logged commands. */
	redact: boolean
	/**
	 * Apply only the detected dialect's patterns. Default false: see the note
	 * on detectDialect below. Enabling this reduces false positives at the
	 * cost of silent false negatives when detection is wrong.
	 */
	strictDialect: boolean
	/** Log the raw tool payload. Diagnostic only; may contain sensitive data. */
	logInputPreview: boolean
}

// ===========================================================================
// Configuration
// ===========================================================================

export const DEFAULT_CONFIG: Config = {
	mode: 'enforce',
	context: {
		E1_regulatedData: false,
		E2_deploysToProduction: false,
		E3_publicFacing: false,
		E4_ingestsUntrustedContent: false,
		E5_auditObligation: false,
	},
	overrides: {},
	redact: true,
	strictDialect: false,
	logInputPreview: false,
}

let CONFIG: Config = structuredClone(DEFAULT_CONFIG)

export function getConfig(): Config {
	return CONFIG
}

/** Replace the active configuration. Used by the plugin at load and by tests. */
export function setConfig(partial: Partial<Config>): Config {
	CONFIG = {
		...structuredClone(DEFAULT_CONFIG),
		...partial,
		context: { ...DEFAULT_CONFIG.context, ...(partial.context ?? {}) },
		overrides: { ...(partial.overrides ?? {}) },
	}
	return CONFIG
}

export function resetConfig(): Config {
	CONFIG = structuredClone(DEFAULT_CONFIG)
	return CONFIG
}

/**
 * Read configuration from disk. A malformed or absent file falls back to
 * defaults rather than failing open, and the reason is reported by the caller.
 */
export function loadConfigFile(path: string): { config: Config; note: string } {
	let raw: string
	try {
		raw = readFileSync(path, 'utf8')
	} catch {
		return { config: resetConfig(), note: 'no config file found, using defaults' }
	}
	try {
		const parsed = JSON.parse(raw) as Partial<Config>
		if (parsed.mode && parsed.mode !== 'enforce' && parsed.mode !== 'observe') {
			return { config: resetConfig(), note: `invalid mode "${parsed.mode}", using defaults` }
		}
		return { config: setConfig(parsed), note: 'config loaded' }
	} catch (err) {
		return { config: resetConfig(), note: `config file is not valid JSON (${err}), using defaults` }
	}
}

// ===========================================================================
// Workspace
// ===========================================================================

let WORKSPACE_ROOT = ''

export function setWorkspaceRoot(p: string) {
	WORKSPACE_ROOT = p
}

const norm = (p: string) => p.replace(/\\/g, '/').toLowerCase()

// ===========================================================================
// Shell dialect
// ===========================================================================

/**
 * Infer which shell a command is written for.
 *
 * IMPORTANT: by default this result is recorded for diagnostics but does NOT
 * gate which patterns are applied. Both dialects are matched against every
 * command.
 *
 * The reasoning: applying only the detected dialect reduces false positives,
 * but any detection error produces a silent false negative — the rules for
 * the other dialect simply never run, and nothing indicates a gap. For a
 * security control, a visible false positive is preferable to an invisible
 * false negative. Set strictDialect to opt into single-dialect matching.
 *
 * Detection is heuristic. Many commands (git, npm, docker) are identical in
 * both shells and are reported as the platform default.
 */
export function detectDialect(cmd: string): Dialect {
	// Verb-Noun cmdlets, PowerShell variables, and PowerShell-only switches.
	if (/\$env:|\b(?:Get|Set|New|Remove|Invoke|Write|Test|Add|Clear|Start|Select|Measure|Out|Convert(?:To|From))-[A-Z]\w+/.test(cmd)) return 'pwsh'
	if (/\s-(?:Recurse|Force|Verb|Path|LiteralPath|ErrorAction)\b/i.test(cmd)) return 'pwsh'
	if (/\bEnv:/i.test(cmd)) return 'pwsh'

	// POSIX-only constructs.
	if (/(^|\s)(sudo|doas|printenv|chmod|chown|awk|sed)\b/.test(cmd)) return 'posix'
	if (/\$\{?\w+\}?|2>&1|\|\s*(?:grep|xargs|tee)\b|^\s*\.\/|~\//.test(cmd)) return 'posix'
	if (/\s-[a-z]{1,3}(\s|$)/.test(cmd)) return 'posix'   // single-dash short flags

	return process.platform === 'win32' ? 'pwsh' : 'posix'
}

// ===========================================================================
// Path extraction
// ===========================================================================

/**
 * Paths referenced by a structured patch payload (OBS-006). The agent's
 * default edit tool passes file paths inside the patch text rather than in a
 * dedicated field, so path-based rules must look here as well.
 */
export function patchPaths(i: Record<string, unknown>): string[] {
	const text = String(i.patchText ?? i.patch ?? '')
	if (!text) return []
	return [...text.matchAll(/^\*\*\* (?:Add|Update|Delete|Move to) File:\s*(.+)$/gim)]
		.map((m) => m[1].trim())
}

/** Every file path a tool call touches, from a direct field or a patch payload. */
export function pathsOf(i: Record<string, unknown>): string[] {
	const direct = String(i.path ?? i.file_path ?? i.filePath ?? i.target_file ?? '')
	return direct ? [direct] : patchPaths(i)
}

const anyPath = (i: Record<string, unknown>, re: RegExp) => pathsOf(i).some((p) => re.test(p))

/** True if a patch payload deletes a file. */
export const isDelete = (i: Record<string, unknown>) =>
	/^\*\*\* Delete File:/im.test(String(i.patchText ?? i.patch ?? ''))

// ===========================================================================
// Tool name sets
// ===========================================================================

/** Verify against `amp tools list`; names vary between agent versions. */
export const READ_TOOLS = new Set(['Read', 'read_file', 'Grep', 'grep', 'glob', 'list_directory'])
export const EDIT_TOOLS = new Set(['edit_file', 'create_file', 'apply_patch', 'edit', 'create'])
export const SHELL_TOOLS = new Set(['Bash', 'bash', 'shell_command'])

/** Case-insensitive: PowerShell cmdlets are case-insensitive and POSIX
 *  commands are conventionally lowercase, so `i` is safe for both. */
const rx = (s: string) => new RegExp(s, 'i')

// ===========================================================================
// Rules
// ===========================================================================

/**
 * Evaluated first-match-wins, ordered NARROWEST TO BROADEST.
 *
 * This is not the same as ordering by tier (OBS-002). A broad low-tier rule
 * placed early will shadow narrow high-tier rules below it. The section
 * headers below are documentation; correctness depends on array position.
 * Where the two conflict, position wins — see A6, which must precede A3
 * because both match the same edit tool.
 */
export const RULES: Rule[] = [

	// ---------------- T4 PROHIBITED: version control ----------------

	{ id: 'D8', tier: 4, label: 'Force push to a shared branch',
	  posix: rx(String.raw`\bgit\s+push\b.*(--force|--force-with-lease|(^|\s)-f(\s|$))`),
	  pwsh:  rx(String.raw`\bgit\s+push\b.*(--force|--force-with-lease|(^|\s)-f(\s|$))`) },

	{ id: 'D7', tier: 4, label: 'Push to a protected branch',
	  posix: rx(String.raw`\bgit\s+push\b[^;|&]*\b(main|master|develop|release)\b`),
	  pwsh:  rx(String.raw`\bgit\s+push\b[^;|&]*\b(main|master|develop|release)\b`) },

	{ id: 'D10', tier: 4, label: 'Delete a repository',
	  posix: rx(String.raw`\brm\s+(-[a-z]*\s+)*\.git\b|\bgh\s+repo\s+delete\b`),
	  pwsh:  rx(String.raw`\b(Remove-Item|ri|rd|rmdir)\b[^;|&]*\.git\b|\bgh\s+repo\s+delete\b`) },

	{ id: 'D13', tier: 4, label: 'Commit under another identity',
	  posix: rx(String.raw`\bgit\s+commit\b[^;|&]*--author`),
	  pwsh:  rx(String.raw`\bgit\s+commit\b[^;|&]*--author`) },

	// ---------------- T4 PROHIBITED: secrets and privilege ----------------

	{ id: 'G2', tier: 4, label: 'Access a credential store or secret file',
	  posix: rx(String.raw`(^|[\s/'"])\.env(\.|$|['"\s])|\.pem\b|\bid_rsa\b|\.ssh/|\.aws/|\bcredentials\b|\.netrc\b|\bkeychain\b`),
	  pwsh:  rx(String.raw`(^|[\s\\/'"])\.env(\.|$|['"\s])|\.pem\b|\bid_rsa\b|\.ssh\\|\.aws\\|\bcredentials\b|\bGet-Credential\b|\bConvertTo-SecureString\b`),
	  tool: (t, i) => (READ_TOOLS.has(t) || EDIT_TOOLS.has(t)) &&
	        anyPath(i, rx(String.raw`(^|[\\/])\.env(\.|$)|\.pem$|id_rsa|[\\/]\.ssh[\\/]|[\\/]\.aws[\\/]`)) },

	{ id: 'G1', tier: 4, label: 'Enumerate environment variables',
	  posix: rx(String.raw`(^|[\s;|&])(env|printenv)(\s|$)`),
	  pwsh:  rx(String.raw`\bGet-ChildItem\s+Env:|\bdir\s+Env:|\$env:\w+\s*(\||>)`) },

	{ id: 'B6', tier: 4, label: 'Run with elevated privileges',
	  posix: rx(String.raw`(^|[\s;|&])(sudo|doas)\s|(^|[\s;|&])su\s+-`),
	  pwsh:  rx(String.raw`-Verb\s+RunAs|\bStart-Process\b[^;|&]*RunAs|\bsudo\b`) },

	{ id: 'B8', tier: 4, label: 'Execute remotely fetched code',
	  posix: rx(String.raw`\b(curl|wget)\b[^;|&]*\|\s*(ba|z|d)?sh\b`),
	  pwsh:  rx(String.raw`\b(Invoke-WebRequest|iwr|curl|Invoke-RestMethod|irm)\b[^;|&]*\|\s*(iex|Invoke-Expression)\b|\biex\s*\(`) },

	// ---------------- T4 PROHIBITED: control integrity ----------------

	{ id: 'K2', tier: 4, label: 'Modify agent configuration or plugins',
	  posix: rx(String.raw`(>|>>|\btee\b|\bsed\s+-i\b|\brm\b|\bmv\b)[^;|&]*(AGENTS?\.md|CLAUDE\.md|\.amp[/\\](plugins|settings|tier-policy))`),
	  pwsh:  rx(String.raw`\b(Out-File|Set-Content|Add-Content|Remove-Item|Move-Item|ri|mv)\b[^;|&]*(AGENTS?\.md|CLAUDE\.md|\.amp[/\\](plugins|settings|tier-policy))`),
	  tool: (t, i) => EDIT_TOOLS.has(t) &&
	        anyPath(i, rx(String.raw`AGENTS?\.md$|CLAUDE\.md$|\.amp[/\\]plugins[/\\]|\.amp[/\\](settings|tier-policy)\.json$`)) },

	{ id: 'L3', tier: 4, label: 'Tamper with logs or audit records',
	  posix: rx(String.raw`\b(rm|truncate|shred)\b[^;|&]*\.(log|jsonl|audit)\b|\bjournalctl\b[^;|&]*--vacuum|>\s*[^;|&]*\.(log|jsonl)\b`),
	  pwsh:  rx(String.raw`\b(Remove-Item|Clear-Content|ri|del)\b[^;|&]*\.(log|jsonl|audit)\b|\bClear-EventLog\b|\bWevtutil\s+cl\b`),
	  tool: (t, i) => EDIT_TOOLS.has(t) && anyPath(i, rx(String.raw`\.(log|jsonl|audit)$`)) },

	// ---------------- T4 PROHIBITED: supply chain and infrastructure ----------------

	{ id: 'C7', tier: 4, label: 'Change package registry source',
	  posix: rx(String.raw`\bnpm\s+config\s+set\s+registry\b|\bpip\s+config\s+set\b[^;|&]*index-url|\byarn\s+config\s+set\s+registry\b`),
	  pwsh:  rx(String.raw`\bnpm\s+config\s+set\s+registry\b|\bpip\s+config\s+set\b[^;|&]*index-url|\bRegister-PSRepository\b|\bSet-PSRepository\b`) },

	{ id: 'H5', tier: 4, label: 'Destructive database operation',
	  posix: rx(String.raw`\b(drop\s+(table|database|schema)|truncate\s+table|delete\s+from)\b`),
	  pwsh:  rx(String.raw`\b(drop\s+(table|database|schema)|truncate\s+table|delete\s+from)\b`) },

	{ id: 'I6', tier: 4, label: 'Deploy to production',
	  posix: rx(String.raw`\b(kubectl|helm|terraform\s+apply|serverless\s+deploy|eb\s+deploy)\b[^;|&]*\b(prod|production)\b`),
	  pwsh:  rx(String.raw`\b(kubectl|helm|terraform\s+apply|serverless\s+deploy)\b[^;|&]*\b(prod|production)\b`) },

	{ id: 'J5', tier: 4, label: 'Modify identity or access policy',
	  posix: rx(String.raw`\baws\s+iam\b|\bgcloud\s+projects\s+(add|remove)-iam|\baz\s+role\s+assignment\b`),
	  pwsh:  rx(String.raw`\baws\s+iam\b|\bgcloud\s+projects\s+(add|remove)-iam|\baz\s+role\s+assignment\b|\bSet-Acl\b|\bAdd-LocalGroupMember\b`) },

	{ id: 'J3', tier: 4, label: 'Apply infrastructure changes',
	  posix: rx(String.raw`\bterraform\s+(apply|destroy)\b|\bpulumi\s+up\b|\bcdk\s+deploy\b`),
	  pwsh:  rx(String.raw`\bterraform\s+(apply|destroy)\b|\bpulumi\s+up\b|\bcdk\s+deploy\b`) },

	// ---------------- T3 APPROVAL REQUIRED ----------------

	{ id: 'A7', tier: 3, label: 'Recursive or forced delete',
	  posix: rx(String.raw`\brm\b[^;|&]*(-[a-z]*[rRf][a-z]*)\s`),
	  pwsh:  rx(String.raw`\b(Remove-Item|ri|rd|rmdir)\b[^;|&]*-(Recurse|Force)\b`) },

	{ id: 'C2', tier: 3, label: 'Add or install a dependency',
	  posix: rx(String.raw`\b(npm|pnpm|yarn)\s+(i|add|install)\b|\bpip3?\s+install\b|\bcargo\s+add\b|\bgo\s+get\b|\bgem\s+install\b|\bapt(-get)?\s+install\b|\bbrew\s+install\b`),
	  pwsh:  rx(String.raw`\b(npm|pnpm|yarn)\s+(i|add|install)\b|\bpip3?\s+install\b|\bcargo\s+add\b|\bgo\s+get\b|\bInstall-Module\b|\bInstall-Package\b|\bchoco\s+install\b|\bwinget\s+install\b`) },

	{ id: 'D9', tier: 3, label: 'Delete a remote branch',
	  posix: rx(String.raw`\bgit\s+push\b[^;|&]*(--delete|\s:\w)`),
	  pwsh:  rx(String.raw`\bgit\s+push\b[^;|&]*(--delete|\s:\w)`) },

	{ id: 'D11', tier: 3, label: 'Modify git configuration or hooks',
	  posix: rx(String.raw`\bgit\s+config\b|\.git[/\\]hooks[/\\]`),
	  pwsh:  rx(String.raw`\bgit\s+config\b|\.git[/\\]hooks[/\\]`) },

	{ id: 'D5', tier: 3, label: 'Rewrite local history',
	  posix: rx(String.raw`\bgit\s+(reset\s+--hard|rebase|filter-branch|commit\b[^;|&]*--amend)`),
	  pwsh:  rx(String.raw`\bgit\s+(reset\s+--hard|rebase|filter-branch|commit\b[^;|&]*--amend)`) },

	{ id: 'F4', tier: 3, label: 'Outbound network request',
	  posix: rx(String.raw`\b(curl|wget|nc|ncat|ssh|scp|rsync)\b`),
	  pwsh:  rx(String.raw`\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl|wget|New-Object\s+Net\.WebClient|ssh|scp)\b`) },

	{ id: 'A5', tier: 3, label: 'Write outside the workspace',
	  tool: (t, i) => {
		if (!EDIT_TOOLS.has(t)) return false
		return pathsOf(i).some((p) => {
			if (!/^([a-zA-Z]:[\\/]|\/|\.\.[\\/]|~[\\/])/.test(p)) return false   // relative == inside
			return WORKSPACE_ROOT ? !norm(p).startsWith(norm(WORKSPACE_ROOT)) : true
		})
	  } },

	{ id: 'A8', tier: 3, label: 'Modify an ignore or exclusion file',
	  tool: (t, i) => EDIT_TOOLS.has(t) &&
	        anyPath(i, rx(String.raw`\.gitignore$|\.dockerignore$|\.npmignore$`)) },

	{ id: 'I3', tier: 3, label: 'Trigger a pipeline or workflow',
	  posix: rx(String.raw`\bgh\s+workflow\s+run\b|\bgh\s+run\s+rerun\b`),
	  pwsh:  rx(String.raw`\bgh\s+workflow\s+run\b|\bgh\s+run\s+rerun\b`) },

	// ---------------- T2 NOTIFY ----------------
	// Position note: A6 must precede A3 (T1) because both match the same edit
	// tool, and first-match-wins. Ordering here is by specificity, not tier.

	{ id: 'D6', tier: 2, label: 'Push to a branch',
	  posix: rx(String.raw`\bgit\s+push\b`),
	  pwsh:  rx(String.raw`\bgit\s+push\b`) },

	{ id: 'E2', tier: 2, label: 'Open or edit a pull request',
	  posix: rx(String.raw`\bgh\s+pr\s+(create|edit|comment)\b`),
	  pwsh:  rx(String.raw`\bgh\s+pr\s+(create|edit|comment)\b`) },

	{ id: 'A6', tier: 2, label: 'Delete a file',
	  posix: rx(String.raw`(^|[\s;|&])rm\s`),
	  pwsh:  rx(String.raw`\b(Remove-Item|ri|del|erase)\b`),
	  tool: (t, i) => t === 'delete_file' || t === 'remove_file' ||
	        (EDIT_TOOLS.has(t) && isDelete(i)) },

	{ id: 'C3', tier: 2, label: 'Update dependencies',
	  posix: rx(String.raw`\b(npm|pnpm|yarn)\s+(update|upgrade|audit\s+fix)\b|\bpip3?\s+install\s+-U\b`),
	  pwsh:  rx(String.raw`\b(npm|pnpm|yarn)\s+(update|upgrade|audit\s+fix)\b|\bUpdate-Module\b`) },

	{ id: 'A4w', tier: 2, label: 'Write to a file via shell redirection',
	  posix: rx(String.raw`(>|>>)\s*\S|\btee\b`),
	  pwsh:  rx(String.raw`\b(Out-File|Set-Content|Add-Content)\b|(>|>>)\s*\S`) },

	{ id: 'D4', tier: 2, label: 'Commit locally',
	  posix: rx(String.raw`\bgit\s+commit\b`),
	  pwsh:  rx(String.raw`\bgit\s+commit\b`) },

	// ---------------- T1 AUTONOMOUS ----------------

	{ id: 'B1', tier: 1, label: 'Run tests, linters, or build',
	  posix: rx(String.raw`\b(npm|pnpm|yarn)\s+(test|run\s+(test|lint|build|typecheck))\b|\bpytest\b|\bgo\s+test\b|\bcargo\s+(test|build|check|clippy)\b|\bmake\s+(test|build|lint)\b|\bdotnet\s+(test|build)\b|\bmvn\s+(test|verify)\b|\bgradle\s+(test|build)\b|\beslint\b|\bruff\b|\btsc\b`),
	  pwsh:  rx(String.raw`\b(npm|pnpm|yarn)\s+(test|run\s+(test|lint|build|typecheck))\b|\bpytest\b|\bgo\s+test\b|\bcargo\s+(test|build|check|clippy)\b|\bdotnet\s+(test|build)\b|\bInvoke-Pester\b|\bgradle\s+(test|build)\b|\beslint\b|\bruff\b|\btsc\b`) },

	{ id: 'D1', tier: 1, label: 'Read repository state',
	  posix: rx(String.raw`\bgit\s+(status|log|diff|show|blame|branch|remote|describe|rev-parse)\b`),
	  pwsh:  rx(String.raw`\bgit\s+(status|log|diff|show|blame|branch|remote|describe|rev-parse)\b`) },

	{ id: 'A1s', tier: 1, label: 'Read-only inspection (shell)',
	  posix: rx(String.raw`^\s*(cat|less|more|head|tail|ls|pwd|find|grep|rg|wc|file|stat|which|echo|date|whoami)\b`),
	  pwsh:  rx(String.raw`^\s*(Get-Content|gc|type|Get-ChildItem|gci|ls|dir|Get-Location|pwd|Select-String|sls|Measure-Object|Get-Item|Test-Path|Write-Output|Write-Host|echo|Get-Date|Resolve-Path)\b`) },

	{ id: 'A1', tier: 1, label: 'Read a file',
	  tool: (t) => READ_TOOLS.has(t) },

	{ id: 'A3', tier: 1, label: 'Create or modify a file in the workspace',
	  tool: (t) => EDIT_TOOLS.has(t) },

	// ---------------- CATCH-ALL — MUST BE LAST (OBS-002) ----------------

	{ id: 'B5', tier: 3, label: 'Unclassified shell command',
	  posix: /.*/, pwsh: /.*/ },
]

export const UNCLASSIFIED: Rule = { id: 'UNKNOWN', tier: 2, label: 'Unclassified action' }
export const RULE_ERROR: Rule = { id: 'RULE-ERROR', tier: 3, label: 'Rule evaluation failed' }

// ===========================================================================
// Classification
// ===========================================================================

/**
 * Split a shell command into independently classifiable segments (OBS-001).
 *
 * Limitation: naive splitting. Separators inside quoted strings or subshells
 * are misinterpreted. Correct handling requires real shell parsing, which is
 * out of scope for this implementation.
 */
export function segments(cmd: string): string[] {
	return cmd
		.split(/;|&&|\|\||\||\n/)
		.map((s) => s.trim())
		.filter(Boolean)
}

function matchRule(rule: Rule, tool: string, text: string | null, input: Record<string, unknown>, dialect: Dialect): boolean {
	if (rule.tool?.(tool, input)) return true
	if (!text) return false
	if (CONFIG.strictDialect) {
		return dialect === 'pwsh' ? !!rule.pwsh?.test(text) : !!rule.posix?.test(text)
	}
	return !!rule.posix?.test(text) || !!rule.pwsh?.test(text)
}

/** Classify a single segment or tool call. Returns the first matching rule. */
export function classifyOne(tool: string, text: string | null, input: Record<string, unknown>, dialect: Dialect = 'posix'): Rule {
	for (const rule of RULES) {
		try {
			if (matchRule(rule, tool, text, input, dialect)) return rule
		} catch {
			// A rule that throws must not silently allow the action.
			return RULE_ERROR
		}
	}
	return UNCLASSIFIED
}

/** Apply any configured per-rule tier override. */
function withOverride(rule: Rule): Rule {
	const o = CONFIG.overrides[rule.id]
	return o && o !== rule.tier ? { ...rule, tier: o } : rule
}

/**
 * Classify a whole tool call. For shell commands every segment is classified
 * and the highest tier found governs the entire command, because a shell line
 * cannot be partially executed (OBS-001).
 */
export function classify(tool: string, shell: string | null, input: Record<string, unknown>) {
	if (!shell) {
		const rule = withOverride(classifyOne(tool, null, input))
		return { worst: rule, all: [{ segment: null as string | null, rule }], dialect: null as Dialect | null }
	}
	const dialect = detectDialect(shell)
	const parts = segments(shell)
	const all = (parts.length ? parts : [shell]).map((segment) => ({
		segment,
		rule: withOverride(classifyOne(tool, segment, input, dialect)),
	}))
	
	// Some rules describe composition rather than any single segment (B8, a
	// pipe into a shell interpreter). Segmentation removes the separator those
	// rules match on, so the whole command is classified too, and the highest
	// tier across both views governs.
	if (parts.length > 1) {
		all.push({
			segment: shell,
			rule: withOverride(classifyOne(tool, shell, input, dialect)),
		})
	}
	
	const worst = all.reduce((a, b) => (b.rule.tier > a.rule.tier ? b : a)).rule
	return { worst, all, dialect }}

/**
 * Raise the tier one step per applicable context modifier, capped at T3.
 * T4 is returned unchanged: a categorical prohibition is assigned by design
 * and cannot be reached, or relaxed, by accumulating quantitative risk.
 */
export function escalate(base: Tier): { tier: Tier; applied: string[] } {
	if (base === 4) return { tier: 4, applied: [] }
	const applied = Object.entries(CONFIG.context).filter(([, v]) => v).map(([k]) => k.split('_')[0])
	return { tier: Math.min(3, base + applied.length) as Tier, applied }
}

// ===========================================================================
// Redaction
// ===========================================================================

/**
 * Remove credential-shaped substrings before a command is written to the
 * decision log. An audit record that captures raw commands will eventually
 * capture a secret passed on a command line, and the log is a plaintext file
 * inside the workspace.
 *
 * Limitations: pattern-based, so novel credential formats pass through, and
 * high-entropy strings that are not secrets (hashes, IDs) may be redacted
 * unnecessarily. Redaction reduces exposure; it does not remove the need to
 * treat the log as sensitive.
 */
const REDACTIONS: Array<[RegExp, string]> = [
	// --password=x, --token x, --api-key=x
	[/(-{1,2}(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key)[=\s]+)\S+/gi, '$1***'],
	// Authorization headers
	[/((?:Authorization|X-Api-Key)\s*:\s*(?:Bearer|Basic|Token)?\s*)\S+/gi, '$1***'],
	// Recognisable provider key prefixes
	[/\b(sk-|pk-|ghp_|gho_|ghu_|ghs_|github_pat_|xox[baprs]-|AIza)[A-Za-z0-9_-]{8,}/g, '$1***'],
	// AWS access key IDs
	[/\bAKIA[0-9A-Z]{16}\b/g, 'AKIA***'],
	// Credentials embedded in a URL
	[/(:\/\/[^:@\s/]+:)[^@\s]+(@)/g, '$1***$2'],
	// PowerShell secure-string literals
	[/((?:ConvertTo-SecureString|-AsPlainText)\s+)(['"])[^'"]+\2/gi, "$1$2***$2"],
	// Long opaque tokens
	[/\b[A-Za-z0-9_-]{40,}\b/g, '***'],
]

export function redact(text: string): string {
	if (!CONFIG.redact) return text
	return REDACTIONS.reduce((acc, [re, sub]) => acc.replace(re, sub), text)
}

// ===========================================================================
// Plugin entry point
// ===========================================================================

export default function (amp: PluginAPI) {
	const root = amp.system.workspaceRoot
		? amp.helpers.filePathFromURI(amp.system.workspaceRoot)
		: process.cwd()

	setWorkspaceRoot(root)

	const configPath = `${root}/.amp/tier-policy.json`
	const logPath = `${root}/.amp/tier-policy-log.jsonl`
	const { config, note } = loadConfigFile(configPath)

	amp.logger.log(`tier-policy v0.3: ${note}`)
	amp.logger.log(`tier-policy: mode=${config.mode} rules=${RULES.length} redact=${config.redact} root=${root}`)
	if (config.mode === 'observe') {
		amp.logger.log('tier-policy: OBSERVE MODE — decisions are recorded but nothing is blocked')
	}

	let logBroken = false

	function record(entry: Record<string, unknown>) {
		if (logBroken) return
		try {
			mkdirSync(dirname(logPath), { recursive: true })
			appendFileSync(logPath, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n', 'utf8')
		} catch (err) {
			logBroken = true
			amp.logger.log(`tier-policy: LOGGING DISABLED, write failed: ${err}`)
		}
	}

	amp.on('tool.call', async (event, ctx): Promise<ToolCallResult> => {
		const cfg = getConfig()
		const shell = amp.helpers.shellCommandFromToolCall(event as ToolCall)?.command ?? null
		const { worst, all, dialect } = classify(event.tool, shell, event.input)
		const { tier, applied } = escalate(worst.tier)

		const trigger = all.find((s) => s.rule.id === worst.id)?.segment ?? null

		const base: Record<string, unknown> = {
			mode: cfg.mode,
			label: worst.label,
			baseTier: worst.tier,
			effectiveTier: tier,
			command: shell ? redact(shell).slice(0, 400) : null,
			ruleID: worst.id,
			modifiers: applied,
			tool: event.tool,
			dialect,
			segmentCount: all.length,
			triggerSegment: trigger ? redact(trigger).slice(0, 200) : null,
			paths: pathsOf(event.input).slice(0, 5),
			toolUseID: event.toolUseID,
			threadID: event.thread.id,
		}
		if (cfg.logInputPreview) {
			base.inputPreview = redact(JSON.stringify(event.input)).slice(0, 400)
		}

		// ---- Observe mode: classify and record, enforce nothing. ----
		if (cfg.mode === 'observe') {
			const wouldHave = tier === 1 ? 'auto-allowed'
				: tier === 2 ? 'notified'
				: tier === 3 ? 'approval-required'
				: 'blocked'
			record({ ...base, outcome: 'observed', wouldHave })
			return { action: 'allow' }
		}

		// ---- T1: proceed silently. ----
		if (tier === 1) {
			record({ ...base, outcome: 'auto-allowed' })
			return { action: 'allow' }
		}

		// ---- T2: proceed, but make it visible. ----
		if (tier === 2) {
			ctx.logger.log(`[T2] ${worst.label} (${worst.id})`)
			let surfaced = true
			try {
				await ctx.ui.notify(`T2 ${worst.label}: proceeding, logged.`)
			} catch {
				// If the notification cannot be shown, T2 has silently degraded
				// to T1. Record that rather than allowing it to pass unnoticed.
				surfaced = false
			}
			record({ ...base, outcome: 'notified', surfaced })
			return { action: 'allow' }
		}

		// ---- T4: deny. No approval path exists. ----
		if (tier === 4) {
			record({ ...base, outcome: 'blocked' })
			return {
				action: 'reject-and-continue',
				message:
					`Blocked by tier policy: ${worst.label} (${worst.id}) is Tier 4, prohibited. ` +
					(all.length > 1
						? `Triggered by segment: ${trigger}. The whole command is refused because a shell command cannot be partially executed. `
						: '') +
					`There is no approval path for this action. Ask the user to perform it manually if it is genuinely required.`,
			}
		}

		// ---- T3: block until a human approves. ----
		const isActive = amp.activeThread.current?.id === event.thread.id
		if (!isActive) {
			// Nobody is watching this thread, so nobody can approve. Fail closed.
			record({ ...base, outcome: 'denied-no-approver' })
			return {
				action: 'reject-and-continue',
				message: `Blocked: ${worst.label} (${worst.id}) requires approval, and this thread is not active. Re-run it in the foreground.`,
			}
		}

		const breakdown = all.length > 1
			? '\n\n**Segments:**\n' + all.map((s) => `- \`${s.segment}\` → T${s.rule.tier} (${s.rule.id})`).join('\n')
			: ''

		const start = Date.now()
		let approved: boolean
		try {
			approved = await ctx.ui.confirm({
				title: `Approval required (Tier 3): ${worst.label}`,
				message:
					`**Rule:** ${worst.id}\n\n` +
					`**Tool:** ${event.tool}\n\n` +
					(shell ? `**Command:**\n\`\`\`\n${shell}\n\`\`\`` : '') +
					breakdown +
					(applied.length ? `\n\n**Escalated by:** ${applied.join(', ')}` : '') +
					`\n\nAllow this action?`,
				confirmButtonText: 'Approve',
			})
		} catch (err) {
			// No approval interface available. Fail closed rather than assume consent.
			const uiMissing = err instanceof Error && amp.helpers.isPluginUINotAvailableError(err)
			record({ ...base, outcome: uiMissing ? 'denied-no-ui' : 'denied-error' })
			return {
				action: 'reject-and-continue',
				message: `Blocked: ${worst.label} requires approval and no approval interface is available.`,
			}
		}

		record({ ...base, outcome: approved ? 'approved' : 'rejected', latencyMs: Date.now() - start })

		return approved
			? { action: 'allow' }
			: { action: 'reject-and-continue', message: `User declined: ${worst.label} (${worst.id}).` }
	})

	// -------------------------------------------------------------------

	amp.registerCommand(
		'show-policy-summary',
		{ title: 'Show tier policy summary', category: 'tier-policy',
		  description: 'Summarise decisions recorded in this workspace.' },
		async (ctx) => {
			const cfg = getConfig()
			let rows: Array<Record<string, unknown>> = []
			try {
				rows = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
			} catch {
				await ctx.ui.confirm({ title: 'Tier policy summary', message: 'No decisions recorded yet.', confirmButtonText: 'Close' })
				return
			}

			const tally = (key: string) =>
				rows.reduce<Record<string, number>>((acc, r) => {
					const k = String(r[key] ?? 'unknown')
					acc[k] = (acc[k] ?? 0) + 1
					return acc
				}, {})

			const fmt = (o: Record<string, number>) =>
				Object.entries(o).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}=${v}`).join('  ')

			const outcomes = tally('outcome')
			const decided = rows.filter((r) => r.outcome === 'approved' || r.outcome === 'rejected')
			const grantRate = decided.length
				? Math.round((decided.filter((r) => r.outcome === 'approved').length / decided.length) * 100)
				: 0

			const topRules = Object.entries(tally('ruleID')).sort((a, b) => b[1] - a[1]).slice(0, 5)

			const lines = [
				`**Mode:** ${cfg.mode}`,
				`**Decisions recorded:** ${rows.length}`,
				`**By effective tier:** ${fmt(tally('effectiveTier'))}`,
				`**By outcome:** ${fmt(outcomes)}`,
			]
			if (cfg.mode === 'observe') {
				lines.push(`**Would have been:** ${fmt(tally('wouldHave'))}`)
			} else {
				lines.push(`**Approval grant rate:** ${grantRate}% of ${decided.length} decisions`)
			}
			lines.push(`**Most frequent rules:** ${topRules.map(([k, v]) => `${k} (${v})`).join(', ')}`)

			await ctx.ui.confirm({
				title: 'Tier policy summary',
				message: lines.join('\n\n'),
				confirmButtonText: 'Close',
			})
		},
	)
}
