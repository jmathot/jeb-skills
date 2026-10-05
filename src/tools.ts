import type { Plugin } from "@opencode/plugin"
import { runEngine } from "./engine.js"
import { importScript, queryScript, visualizeScript } from "./paths.js"

// The engine keeps the original CLI's command tree. We expose it as OpenCode tools
// under the `jeb` namespace, preserving that shape:
//   jeb query  <endpoint|map|search|get|similar|identifier|evidence|attacks|record-attack>
//   jeb import <import|rebuild|status|abandon|export>
//   jeb visualize
// Each dispatcher takes a `command` selector plus the arguments for that command,
// and forwards them to the matching Python subcommand (which emits JSON).

type SchemaProp = Record<string, any>

const str = (description: string): SchemaProp => ({ type: "string", description })
const int = (description: string): SchemaProp => ({ type: "integer", description })
const bool = (description: string): SchemaProp => ({ type: "boolean", description })
const strArr = (description: string): SchemaProp => ({ type: "array", items: { type: "string" }, description })
const enumStr = (values: string[], description: string): SchemaProp => ({ type: "string", enum: values, description })

const dbPath = str("Project database path; defaults to ./chroma_db in the current project directory.")

// Positional arguments per subcommand (order matters; everything else is a flag).
const QUERY_POSITIONALS: Record<string, string[]> = {
  endpoint: ["target"],
  get: ["target"],
  similar: ["target"],
  identifier: ["target"],
  evidence: ["target"],
  search: ["text"],
  map: [],
  attacks: [],
  "record-attack": [],
}

const IMPORT_POSITIONALS: Record<string, string[]> = {
  import: ["xml_file", "project_dir"],
  rebuild: ["project_dir"],
  status: ["project_dir"],
  abandon: ["capture_id", "project_dir"],
  export: ["project_dir"],
}

interface BuildOpts {
  positionals: string[]
  flagOverrides?: Record<string, string>
  paired?: Record<string, [string, string]>
}

function buildArgv(input: Record<string, any>, opts: BuildOpts): string[] {
  const argv: string[] = []
  const used = new Set<string>(opts.positionals)
  used.add("command")

  for (const key of opts.positionals) {
    const value = input[key]
    if (value !== undefined && value !== null && value !== "") argv.push(String(value))
  }

  for (const [key, value] of Object.entries(input)) {
    if (used.has(key) || value === undefined || value === null || value === "") continue
    const paired = opts.paired?.[key]
    if (paired) {
      argv.push(value ? paired[0] : paired[1])
      continue
    }
    const flag = opts.flagOverrides?.[key] ?? "--" + key.replace(/_/g, "-")
    if (typeof value === "boolean") {
      if (value) argv.push(flag)
      continue
    }
    if (Array.isArray(value)) {
      for (const item of value) argv.push(flag, String(item))
      continue
    }
    argv.push(flag, String(value))
  }
  return argv
}

export async function registerTools(
  ctx: Plugin.Context,
  python: string,
  env: Record<string, string>,
): Promise<void> {
  const cwd = String(ctx.location.directory)

  const call = async (
    script: string,
    argv: string[],
    context: { signal: AbortSignal },
  ): Promise<{ content: string }> => {
    try {
      const res = await runEngine({ python, script, argv, cwd, env, signal: context.signal })
      const text = res.stdout.trim() || res.stderr.trim() || `(no output; exit code ${res.code})`
      return { content: text }
    } catch (err) {
      return { content: JSON.stringify({ error: `could not run engine: ${(err as Error).message}` }) }
    }
  }

  await ctx.tool.transform((editor) => {
    editor.namespace({
      name: "jeb",
      description: "J.E.B.E.D.I.A.H. — investigate an imported Burp Suite capture (local Chroma + Ollama RAG).",
    })

    // ---- jeb query <command> ----
    editor.add({
      name: "query",
      options: { namespace: "jeb" },
      description: [
        "Investigate an imported capture. Set `command`, then the fields for it:",
        "- endpoint: target (path or full URL). The first move for any named route; also host/path/method/depth/limit/no_raw/raw_chars.",
        "- map: list the app; kind/limit/offset and any filters. Scope with kind=endpoint, then kind=auth_model.",
        "- search: text (concepts) and/or filters; collection (structure|behavior|attacks|exchanges), depth, loose.",
        "- get: target (document or exchange id); original=true adds raw HTTP base64.",
        "- similar: target (semantic document id).",
        "- identifier: target (exact value); offset/limit.",
        "- evidence: target (behavior id); signal (content|schema), offset/limit.",
        "- attacks: list recorded findings; vuln_class/verdict/severity, offset/limit.",
        "- record-attack: save a finding; requires vuln_class and endpoint; method/param/payload/status/verdict/evidence/source_id/request/response/event_id.",
        "Returns one JSON object (with a `next` hint of follow-up commands). Structural collections hold protocol facts, not vulnerability labels — search the signal, not the bug name.",
      ].join("\n"),
      input: {
        type: "object",
        additionalProperties: false,
        required: ["command"],
        properties: {
          command: enumStr(
            ["endpoint", "map", "search", "get", "similar", "identifier", "evidence", "attacks", "record-attack"],
            "Which query subcommand to run.",
          ),
          target: str("Positional argument for endpoint/get/similar/identifier/evidence (path, URL, or id)."),
          text: str("Search concepts (search command). Use structural language, not vulnerability jargon."),
          collection: enumStr(["structure", "behavior", "attacks", "exchanges"], "Semantic scope (`--in`) for search/get; similar/get resolve ids. exchanges = full decoded source HTTP."),
          depth: enumStr(["quick", "normal", "deep"], "Retrieval budget preset (default normal)."),
          limit: int("Maximum results."),
          offset: int("Listing offset (metadata listings without query text)."),
          host: str("Filter by hostname."),
          path: str("Filter by URL path."),
          method: strArr("HTTP method(s). Repeatable for map/search/attacks; single for endpoint."),
          status: str("Status filter, e.g. '500', '>=500', '<400' (also the observed status for record-attack)."),
          param: strArr("Require parameter name(s) (record-attack: the tested parameter)."),
          cookie: strArr("Require cookie name(s) (exact, case-sensitive)."),
          missing_header: strArr("Require security header(s) to be absent, e.g. csp, hsts."),
          kind: str("Node kind: endpoint, auth_model, entity."),
          access_control: str("Access-control signal, e.g. open-data, soft-auth-wall."),
          access_class: str("Access classification facet."),
          contains: str("Case-sensitive literal substring (previews, or full source with collection=exchanges)."),
          where: str("Raw metadata filter (advanced)."),
          anon: bool("Only records with no recognized credential."),
          auth: bool("Only credential-bearing records."),
          cors_open: bool("Only wildcard/null CORS observations."),
          include_static: bool("Include static assets (excluded by default)."),
          anon_matches_auth: bool("Only where an anonymous response matched a credentialed one (behavior)."),
          cookie_issues: bool("Only records with cookie-flag issues."),
          jwt: bool("Only records involving JWTs."),
          loose: bool("Disable the distance cutoff (search)."),
          original: bool("Include original HTTP base64 (get)."),
          no_raw: bool("Omit the raw request/response preview (endpoint)."),
          raw_chars: int("Max characters of raw preview (endpoint)."),
          signal: enumStr(["content", "schema"], "Comparison signal for evidence."),
          vuln_class: str("Vulnerability class — required for record-attack; filter for attacks."),
          verdict: enumStr(["vulnerable", "not_vulnerable", "inconclusive"], "Finding verdict (record-attack / attacks filter)."),
          severity: str("Finding severity (record-attack / attacks filter)."),
          endpoint: str("Absolute endpoint URL (required for record-attack)."),
          payload: str("Payload used (record-attack)."),
          source_id: str("Supporting document id (record-attack)."),
          evidence: str("Raw evidence text (record-attack)."),
          tool: str("Tool used for the test (record-attack)."),
          request: str("Raw request text (record-attack)."),
          request_file: str("Path to a request file (record-attack; alternative to request)."),
          response: str("Raw response text (record-attack)."),
          response_file: str("Path to a response file (record-attack; alternative to response)."),
          event_id: str("Idempotency key (record-attack); reuse only for identical inputs."),
          db_path: dbPath,
        },
      },
      execute: async (input: any, context) => {
        const command = String(input.command)
        const argv = [command, ...buildArgv(input, { positionals: QUERY_POSITIONALS[command] ?? [], flagOverrides: { collection: "--in" } })]
        return call(queryScript, argv, context)
      },
    })

    // ---- jeb import <command> ----
    editor.add({
      name: "import",
      options: { namespace: "jeb" },
      description: [
        "Build or maintain a capture's Chroma database. Set `command`, then its fields:",
        "- import: xml_file (Burp XML) and optional project_dir; auth_cookies/auto_detect/rebuild. Streams directly into Chroma; omitted options inherit saved project settings.",
        "- rebuild: project_dir — rebuild derived indexes from retained observations (no XML needed). Preserves finding IDs.",
        "- status: project_dir — report capture states and index state; run after an error.",
        "- abandon: capture_id and project_dir — exclude a failed/interrupted capture (evidence retained); rebuild afterward.",
        "- export: project_dir with collection and output — write one collection as NDJSON to a path that must not exist.",
        "Never delete the database to fix a schema mismatch; rebuild instead.",
      ].join("\n"),
      input: {
        type: "object",
        additionalProperties: false,
        required: ["command"],
        properties: {
          command: enumStr(["import", "rebuild", "status", "abandon", "export"], "Which import subcommand to run."),
          xml_file: str("Burp Suite XML export (import command)."),
          project_dir: str("Engagement project directory (default: current directory)."),
          capture_id: str("Capture id to abandon (abandon command)."),
          auth_cookies: strArr("Additional recognized credential cookie names (import). Replaces custom names for the whole corpus."),
          auto_detect: bool("Enable/disable origin-scoped login-cookie learning (import). Omit to inherit the saved setting."),
          rebuild: bool("Force derived index rebuild during import even if versions match."),
          collection: enumStr(["structure", "behavior", "attacks", "captures", "exchanges", "identifiers"], "Collection to export (export command)."),
          output: str("NDJSON destination path; must not already exist (export command)."),
        },
      },
      execute: async (input: any, context) => {
        const command = String(input.command)
        const argv = [
          command,
          ...buildArgv(input, {
            positionals: IMPORT_POSITIONALS[command] ?? [],
            paired: { auto_detect: ["--auto-detect-auth-cookies", "--no-auto-detect-auth-cookies"] },
          }),
        ]
        return call(importScript, argv, context)
      },
    })

    // ---- jeb visualize ----
    editor.add({
      name: "visualize",
      options: { namespace: "jeb" },
      description:
        "Render an interactive HTML view of the capture (site-map graph or embedding space) to a file. Needs the viz dependencies (installed at bootstrap).",
      input: {
        type: "object",
        additionalProperties: false,
        required: ["out"],
        properties: {
          mode: enumStr(["graph", "embedding"], "Visualization mode (default embedding). graph = site map."),
          out: str("Output HTML file path."),
          sample: int("Embedding mode: sample N vectors before loading."),
          db_path: dbPath,
        },
      },
      execute: async (input: any, context) => {
        const argv = buildArgv(input, { positionals: [] })
        return call(visualizeScript, argv, context)
      },
    })
  })
}
