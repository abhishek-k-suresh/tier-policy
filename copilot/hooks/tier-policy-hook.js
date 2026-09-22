#!/usr/bin/env node
/**
 * Tier Policy — GitHub Copilot hook
 *
 * Implements the same four-tier permission model as the Amp plugin, against
 * Copilot's hook API. Unlike the VS Code terminal allow-list, hooks expose a
 * three-valued decision (allow / ask / deny), so all four tiers are
 * expressible here.
 *
 *   T1 Autonomous  -> allow   (silent)
 *   T2 Notify      -> allow   (logged, reason surfaced)
 *   T3 Approval    -> ask     (user decides)
 *   T4 Prohibited  -> deny    (no approval path)
 *
 * Usage — invoked by Copilot, not by hand:
 *   node tier-policy-hook.js pre    # preToolUse  — decides
 *   node tier-policy-hook.js post   # postToolUse — logs only
 *
 * Reads the event payload as JSON on stdin, writes a decision as JSON to
 * stdout. Supported in Copilot CLI and Copilot cloud agent. NOT supported in
 * VS Code agent mode, which uses chat.tools.terminal.autoApprove instead.
 *
 * Fail behaviour: Copilot treats a crash or non-zero exit from a preToolUse
 * command hook as a denial. This script relies on that, and additionally
 * denies explicitly on any internal error, so a broken policy blocks rather
 * than silently permits. Timeouts are fail-open in Copilot and cannot be
 * changed from here; see the coverage report.
 *
 * WIL placement project. Built from public documentation.
 */

const fs = require('node:fs')
const path = require('node:path')

// ===========================================================================
// Configuration
// ===========================================================================

const DEFAULT_CONFIG = {
	mode: 'enforce',                 // 'enforce' | 'observe'
	context: {
		E1_regulatedData: false,
		E2_deploysToProduction: false,
		E3_publicFacing: false,
		E4_ingestsUntrustedContent: false,
		E5_auditObligation: false,
	},
	overrides: {},
	redact: true,
}

function loadConfig(cwd) {
	for (const rel of ['.github/tier-policy.json', '.copilot/tier-policy.json', '.amp/tier-policy.json']) {
		try {
			const parsed = JSON.parse(fs.readFileSync(path.join(cwd, rel), 'utf8'))
			return {
				...DEFAULT_CONFIG,
				...parsed,
				context: { ...DEFAULT_CONFIG.context, ...(parsed.context ?? {}) },
				overrides: { ...(parsed.overrides ?? {}) },
			}
		} catch { /* try the next location */ }
	}
	return DEFAULT_CONFIG
}

// ===========================================================================
// Rules
//
// Mirrors the Amp plugin rule set. Ordered narrowest to broadest; first match
// wins. The catch-all is last. A single source generating both this file and
// the plugin would be the right structure for a production version.
// ===========================================================================

const rx = (s) => new RegExp(s, 'i')
/**
 * Git accepts global flags between the command and the subcommand:
 *   git --no-pager push, git -c user.name=x commit, git -C /path status
 * Agents use these routinely, so every git rule must tolerate them. Written
 * against commands as a human types them, these rules missed entirely.
 */
const GIT = String.raw`\bgit\s+(?:(?:-[cC]\s+\S+|--[\w-]+(?:=\S+)?)\s+)*`
/** [id, tier, label, posixPattern, pwshPattern] — either pattern may be null. */
const SHELL_RULES = [
	// ---- T4 Prohibited ----
	['D8', 4, 'Force push to a shared branch',
		String.raw`${GIT}push\b.*(--force|--force-with-lease|(^|\s)-f(\s|$))`, null],
	['D7', 4, 'Push to a protected branch',
		String.raw`${GIT}push\b[^;|&]*\b(main|master|develop|release)\b`, null],
	['D10', 4, 'Delete a repository',
		String.raw`\brm\s+(-[a-z]*\s+)*\.git\b|\bgh\s+repo\s+delete\b`,
		String.raw`\b(Remove-Item|ri|rd|rmdir)\b[^;|&]*\.git\b|\bgh\s+repo\s+delete\b`],
	['D13', 4, 'Commit under another identity',
		String.raw`${GIT}commit\b[^;|&]*--author`, null],
	['G2', 4, 'Access a credential store or secret file',
		String.raw`(^|[\s/'"])\.env(\.|$|['"\s])|\.pem\b|\bid_rsa\b|[/\\]\.ssh[/\\]|[/\\]\.aws[/\\]|\.netrc\b`,
		String.raw`(^|[\s\\/'"])\.env(\.|$|['"\s])|\.pem\b|\bid_rsa\b|\bGet-Credential\b|\bConvertTo-SecureString\b`],
	['G1', 4, 'Enumerate environment variables',
		String.raw`(^|[\s;|&])(env|printenv)(\s|$)`,
		String.raw`\bGet-ChildItem\s+Env:|\bdir\s+Env:`],
	['B6', 4, 'Run with elevated privileges',
		String.raw`(^|[\s;|&])(sudo|doas)\s|(^|[\s;|&])su\s+-`,
		String.raw`-Verb\s+RunAs|\bStart-Process\b[^;|&]*RunAs`],
	['B8', 4, 'Execute remotely fetched code',
		String.raw`\b(curl|wget)\b[^|]*\|\s*(ba|z|d)?sh\b`,
		String.raw`\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|]*\|\s*(iex|Invoke-Expression)\b|\biex\s*\(`],
	['K2', 4, 'Modify agent configuration or hooks',
		String.raw`(>|>>|\btee\b|\bsed\s+-i\b|\brm\b|\bmv\b)[^;|&]*(AGENTS?\.md|CLAUDE\.md|copilot-instructions\.md|\.github[/\\]hooks|tier-policy)`,
		String.raw`\b(Out-File|Set-Content|Add-Content|Remove-Item|Move-Item)\b[^;|&]*(AGENTS?\.md|copilot-instructions\.md|\.github[/\\]hooks|tier-policy)`],
	['L3', 4, 'Tamper with logs or audit records',
		String.raw`\b(rm|truncate|shred)\b[^;|&]*\.(log|jsonl|audit)\b|\bjournalctl\b[^;|&]*--vacuum|>\s*[^;|&]*\.(log|jsonl)\b`,
		String.raw`\b(Remove-Item|Clear-Content)\b[^;|&]*\.(log|jsonl|audit)\b|\bClear-EventLog\b`],
	['C7', 4, 'Change package registry source',
		String.raw`\bnpm\s+config\s+set\s+registry\b|\bpip\s+config\s+set\b[^;|&]*index-url|\byarn\s+config\s+set\s+registry\b`,
		String.raw`\b(Register-PSRepository|Set-PSRepository)\b`],
	['H5', 4, 'Destructive database operation',
		String.raw`\b(drop\s+(table|database|schema)|truncate\s+table|delete\s+from)\b`, null],
	['I6', 4, 'Deploy to production',
		String.raw`\b(kubectl|helm|terraform\s+apply|serverless\s+deploy|eb\s+deploy)\b[^;|&]*\b(prod|production)\b`, null],
	['J5', 4, 'Modify identity or access policy',
		String.raw`\baws\s+iam\b|\bgcloud\s+projects\s+(add|remove)-iam\b|\baz\s+role\s+assignment\b`,
		String.raw`\b(Set-Acl|Add-LocalGroupMember)\b`],
	['J3', 4, 'Apply infrastructure changes',
		String.raw`\bterraform\s+(apply|destroy)\b|\bpulumi\s+up\b|\bcdk\s+deploy\b`, null],

	// ---- T3 Approval required ----
	['A7', 3, 'Recursive delete',
		String.raw`\brm\b[^;|&]*(-[a-zA-Z]*[rR]|--recursive)`,
		String.raw`\b(Remove-Item|ri|rd|rmdir)\b[^;|&]*-Recurse\b`],
	['C2', 3, 'Add or install a dependency',
		String.raw`\b(npm|pnpm|yarn)\s+(i|add|install)\b|\bpip3?\s+install\b|\bcargo\s+add\b|\bgo\s+get\b|\bgem\s+install\b|\b(apt|apt-get|brew)\s+install\b`,
		String.raw`\b(npm|pnpm|yarn)\s+(i|add|install)\b|\bpip3?\s+install\b|\b(Install-Module|Install-Package)\b|\b(choco|winget)\s+install\b`],
	['D9', 3, 'Delete a remote branch',
		String.raw`${GIT}push\b[^;|&]*(--delete|\s:\w)`, null],
	['D11', 3, 'Modify git configuration or hooks',
		String.raw`${GIT}config\b|\.git[/\\]hooks[/\\]`, null],
	['D5', 3, 'Rewrite local history',
		String.raw`${GIT}(reset\s+--hard|rebase|filter-branch)\b|${GIT}commit\b[^;|&]*--amend`, null],
	['F4', 3, 'Outbound network request',
		String.raw`\b(curl|wget|nc|ncat|ssh|scp|rsync)\b`,
		String.raw`\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl|wget|ssh|scp)\b`],
	['I3', 3, 'Trigger a pipeline or workflow',
		String.raw`\bgh\s+(workflow\s+run|run\s+rerun)\b`, null],

	// ---- T2 Notify ----
	['D6', 2, 'Push to a branch', String.raw`${GIT}push\b`, null],
	['E2', 2, 'Open or edit a pull request', String.raw`\bgh\s+pr\s+(create|edit|comment)\b`, null],
	['A6', 2, 'Delete a file',
		String.raw`(^|[\s;|&])rm\s`, String.raw`\b(Remove-Item|ri|del|erase)\b`],
	['C3', 2, 'Update dependencies',
		String.raw`\b(npm|pnpm|yarn)\s+(update|upgrade|audit\s+fix)\b`, String.raw`\bUpdate-Module\b`],
	['A4w', 2, 'Write to a file via shell redirection',
		String.raw`(>|>>)\s*\S|\btee\b`, String.raw`\b(Out-File|Set-Content|Add-Content)\b`],
	['D4', 2, 'Commit locally', String.raw`${GIT}commit\b`, null],

	// ---- T1 Autonomous ----
	['B1', 1, 'Run tests, linters, or build',
		String.raw`\b(npm|pnpm|yarn)\s+(test|run\s+(test|lint|build|typecheck))\b|\bpytest\b|\bgo\s+test\b|\bcargo\s+(test|build|check|clippy)\b|\bmake\s+(test|build|lint)\b|\b(dotnet|gradle|mvn)\s+(test|build|verify)\b|\b(eslint|ruff|tsc)\b`,
		String.raw`\b(npm|pnpm|yarn)\s+(test|run\s+(test|lint|build))\b|\bpytest\b|\bInvoke-Pester\b|\b(dotnet|gradle)\s+(test|build)\b|\b(eslint|ruff|tsc)\b`],
	['D1', 1, 'Read repository state',
		String.raw`${GIT}(status|log|diff|show|blame|branch|remote|describe|rev-parse)\b`, null],
	['A1s', 1, 'Read-only inspection',
		String.raw`^\s*(cat|less|more|head|tail|ls|pwd|find|grep|rg|wc|file|stat|which|echo|date)\b`,
		String.raw`^\s*(Get-Content|gc|type|Get-ChildItem|gci|dir|Get-Location|Select-String|sls|Get-Item|Test-Path|Write-Output|Write-Host|Resolve-Path)\b`],

	['B7', 3, 'Execute inline interpreter code',
		String.raw`\b(python3?|node|perl|ruby|php)\s+-(c|e)\b`,
		String.raw`\b(python3?|node|perl|ruby)\s+-(c|e)\b|\b(powershell|pwsh)\s+-(Command|EncodedCommand)\b`],
	// ---- Catch-all: must be last ----
	['B5', 3, 'Unclassified shell command', String.raw`.*`, String.raw`.*`],
].map(([id, tier, label, posix, pwsh]) => ({
	id, tier, label,
	posix: posix ? rx(posix) : null,
	pwsh: pwsh ? rx(pwsh) : null,
}))

/** Path-based rules, applied to file tools. Ordered narrowest to broadest. */
const PATH_RULES = [
	['K2', 4, 'Modify agent configuration or hooks',
		String.raw`AGENTS?\.md$|CLAUDE\.md$|copilot-instructions\.md$|\.github[/\\]hooks[/\\]|tier-policy\.(json|js|ts)$`],
	['G2', 4, 'Access a credential store or secret file',
		String.raw`(^|[/\\])\.env(\.|$)|\.pem$|id_rsa|[/\\]\.ssh[/\\]|[/\\]\.aws[/\\]`],
	['L3', 4, 'Tamper with logs or audit records', String.raw`\.(log|jsonl|audit)$`],
	['A8', 3, 'Modify an ignore or exclusion file', String.raw`\.(git|docker|npm)ignore$`],
].map(([id, tier, label, p]) => ({ id, tier, label, path: rx(p) }))

const UNKNOWN = { id: 'UNKNOWN', tier: 2, label: 'Unclassified action' }

// ===========================================================================
// Tool mapping
//
// Copilot tool names, from the hooks reference. PascalCase event names deliver
// Claude-style tool names instead, so both are accepted.
// ===========================================================================

const SHELL_TOOLS = new Set(['bash', 'powershell', 'Bash'])
const READ_TOOLS  = new Set(['view', 'grep', 'glob', 'Read', 'Grep', 'Glob'])
const EDIT_TOOLS  = new Set(['create', 'edit', 'str_replace_editor', 'apply_patch', 'Write', 'Edit'])
const NET_TOOLS   = new Set(['web_fetch', 'WebFetch'])
const TASK_TOOLS  = new Set(['task', 'Agent', 'Task'])

// ===========================================================================
// Classification
// ===========================================================================

/** Split a shell command into independently classifiable segments. */
function segments(cmd) {
	return cmd.split(/;|&&|\|\||\||\n/).map((s) => s.trim()).filter(Boolean)
}

function classifyShellText(text) {
	for (const r of SHELL_RULES) {
		if ((r.posix && r.posix.test(text)) || (r.pwsh && r.pwsh.test(text))) return r
	}
	return UNKNOWN
}

/**
 * Classify a whole shell command. Each segment is classified, and the intact
 * command too, because some rules describe composition rather than any single
 * part (a download piped into an interpreter). The highest tier governs.
 */
function classifyShell(cmd) {
	const parts = segments(cmd)
	const found = parts.map((s) => ({ segment: s, rule: classifyShellText(s) }))
	if (parts.length > 1) found.push({ segment: cmd, rule: classifyShellText(cmd) })
	const worst = found.reduce((a, b) => (b.rule.tier > a.rule.tier ? b : a))
	return { rule: worst.rule, trigger: worst.segment, segmentCount: parts.length }
}

/** Every file path referenced by a tool call, including inside patch payloads. */
function pathsOf(args) {
	if (!args || typeof args !== 'object') return []
	const direct = args.path ?? args.filePath ?? args.file_path ?? args.target_file ?? args.fileName
	if (direct) return [String(direct)]
	const patch = String(args.patchText ?? args.patch ?? args.input ?? '')
	if (!patch) return []
	return [...patch.matchAll(/^\*\*\* (?:Add|Update|Delete|Move to) File:\s*(.+)$/gim)].map((m) => m[1].trim())
}

function classifyPaths(paths) {
	for (const r of PATH_RULES) {
		if (paths.some((p) => r.path.test(p))) return r
	}
	return null
}

function classify(toolName, args) {
	// Shell commands.
	if (SHELL_TOOLS.has(toolName)) {
		const cmd = String(args?.command ?? args?.cmd ?? args?.script ?? '')
		if (!cmd) return { rule: UNKNOWN, trigger: null, segmentCount: 0, paths: [] }
		return { ...classifyShell(cmd), command: cmd, paths: [] }
	}

	const paths = pathsOf(args)

	// File tools: check sensitive paths first, then fall back to the tool class.
	if (EDIT_TOOLS.has(toolName) || READ_TOOLS.has(toolName)) {
		const byPath = classifyPaths(paths)
		if (byPath) return { rule: byPath, trigger: paths[0] ?? null, segmentCount: 0, paths }

		// A file tool whose target cannot be determined is not a known-safe action.
		if (paths.length === 0) {
			return { rule: { id: 'A9', tier: 3, label: 'File operation with undeterminable target' },
						trigger: null, segmentCount: 0, paths }
		}
		const isDelete = /^\*\*\* Delete File:/im.test(String(args?.patchText ?? args?.patch ?? ''))
		if (isDelete) return { rule: { id: 'A6', tier: 2, label: 'Delete a file' }, trigger: paths[0] ?? null, segmentCount: 0, paths }

		return {
			rule: READ_TOOLS.has(toolName)
				? { id: 'A1', tier: 1, label: 'Read a file' }
				: { id: 'A3', tier: 1, label: 'Create or modify a file in the workspace' },
			trigger: paths[0] ?? null, segmentCount: 0, paths,
		}
	}

	// Outbound fetches.
	if (NET_TOOLS.has(toolName)) {
		return { rule: { id: 'F2', tier: 3, label: 'Fetch external content' },
		         trigger: String(args?.url ?? ''), segmentCount: 0, paths: [] }
	}

	// Sub-agents: delegated authority must not exceed the parent's.
	if (TASK_TOOLS.has(toolName)) {
		return { rule: { id: 'K5', tier: 3, label: 'Invoke or spawn a sub-agent' },
		         trigger: null, segmentCount: 0, paths: [] }
	}

	return { rule: UNKNOWN, trigger: null, segmentCount: 0, paths }
}

function escalate(baseTier, cfg) {
	if (baseTier === 4) return { tier: 4, applied: [] }
	const applied = Object.entries(cfg.context).filter(([, v]) => v).map(([k]) => k.split('_')[0])
	return { tier: Math.min(3, baseTier + applied.length), applied }
}

// ===========================================================================
// Redaction
// ===========================================================================

const REDACTIONS = [
	[/(-{1,2}(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key)[=\s]+)\S+/gi, '$1***'],
	[/((?:Authorization|X-Api-Key)\s*:\s*(?:Bearer|Basic|Token)?\s*)\S+/gi, '$1***'],
	[/\b(sk-|pk-|ghp_|gho_|ghu_|ghs_|github_pat_|xox[baprs]-|AIza)[A-Za-z0-9_-]{8,}/g, '$1***'],
	[/\bAKIA[0-9A-Z]{16}\b/g, 'AKIA***'],
	[/(:\/\/[^:@\s/]+:)[^@\s]+(@)/g, '$1***$2'],
	[/\b[A-Za-z0-9_-]{40,}\b/g, '***'],
]

const redact = (text, cfg) =>
	cfg.redact ? REDACTIONS.reduce((acc, [re, sub]) => acc.replace(re, sub), text) : text

// ===========================================================================
// Logging
// ===========================================================================

function record(cwd, entry) {
	try {
		const dir = path.join(cwd, '.github')
		fs.mkdirSync(dir, { recursive: true })
		fs.appendFileSync(
			path.join(dir, 'tier-policy-log.jsonl'),
			JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n',
			'utf8',
		)
	} catch {
		// Logging must never block a decision. The failure is invisible here,
		// which is a known weakness: see the coverage report.
	}
}

// ===========================================================================
// Entry point
// ===========================================================================

function readStdin() {
	try { return fs.readFileSync(0, 'utf8') } catch { return '' }
}

function main() {
	const mode = (process.argv[2] || 'pre').toLowerCase()
	const raw = readStdin()

	let event
	try {
		event = JSON.parse(raw)
	} catch {
		// Malformed input on a decision hook must not be permissive.
		if (mode === 'pre') {
			process.stdout.write(JSON.stringify({
				permissionDecision: 'deny',
				permissionDecisionReason: 'Tier policy could not read the hook payload, so the action was refused.',
			}))
		}
		process.exit(0)
	}
	
	// Accept both the camelCase and VS Code compatible payload shapes.
	const toolName = event.toolName ?? event.tool_name ?? ''
	let toolArgs = event.toolArgs ?? event.tool_input ?? {}
	if (typeof toolArgs === 'string') {
		try { toolArgs = JSON.parse(toolArgs) } catch { toolArgs = { command: toolArgs } }
	}
	const cwd = event.cwd || process.cwd()
	const sessionId = event.sessionId ?? event.session_id ?? null
	const cfg = loadConfig(cwd)

	// ---- postToolUse: record only, never decide. ----
	if (mode === 'post') {
		record(cwd, {
			phase: 'post', sessionId, tool: toolName,
			resultType: event.toolResult?.resultType ?? event.tool_result?.result_type ?? 'unknown',
		})
		process.stdout.write('{}')
		process.exit(0)
	}

	// ---- preToolUse: classify, escalate, decide. ----
	const { rule, trigger, segmentCount, command, paths } = classify(toolName, toolArgs)
	const baseTier = cfg.overrides[rule.id] ?? rule.tier
	const { tier, applied } = escalate(baseTier, cfg)

	const entry = {
		phase: 'pre', mode: cfg.mode, sessionId,
		label: rule.label, baseTier, effectiveTier: tier,
		ruleID: rule.id, modifiers: applied, tool: toolName,
		segmentCount,
		command: command ? redact(command, cfg).slice(0, 400) : null,
		trigger: trigger ? redact(String(trigger), cfg).slice(0, 200) : null,
		paths: (paths ?? []).slice(0, 5),
	}

	// Observation mode: classify and record, enforce nothing.
	if (cfg.mode === 'observe') {
		const wouldHave = tier === 4 ? 'deny' : tier === 3 ? 'ask' : 'allow'
		record(cwd, { ...entry, outcome: 'observed', wouldHave })
		process.stdout.write(JSON.stringify({ permissionDecision: 'allow' }))
		process.exit(0)
	}

	let decision, reason
	if (tier === 4) {
		decision = 'deny'
		reason =
			`Blocked by tier policy: ${rule.label} (${rule.id}) is Tier 4, prohibited. ` +
			(segmentCount > 1 ? `Triggered by: ${trigger}. The whole command is refused because a shell command cannot be partially executed. ` : '') +
			`There is no approval path for this action. Ask the user to perform it manually if it is genuinely required.`
	} else if (tier === 3) {
		decision = 'ask'
		reason =
			`${rule.label} (${rule.id}) requires approval` +
			(applied.length ? `, escalated by ${applied.join(', ')}` : '') + '.'
	} else {
		decision = 'allow'
		reason = tier === 2 ? `${rule.label} (${rule.id}) — permitted and recorded.` : undefined
	}

	record(cwd, { ...entry, outcome: decision })

	const out = { permissionDecision: decision }
	if (reason) out.permissionDecisionReason = reason
	process.stdout.write(JSON.stringify(out))
	process.exit(0)
}

try {
	main()
} catch (err) {
	// Copilot fails closed on a non-zero exit from preToolUse, but say so
	// explicitly rather than relying on that behaviour alone.
	process.stdout.write(JSON.stringify({
		permissionDecision: 'deny',
		permissionDecisionReason: `Tier policy failed to evaluate this action (${err && err.message}), so it was refused.`,
	}))
	process.exit(2)
}
