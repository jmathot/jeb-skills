// Model semantics are shared with Python; connection details never enter index identity.
import profiles from "./embedding-profiles.json" with { type: "json" }
export { profiles }

export interface BuiltConfig {
  env: Record<string, string>
  indexSignature: string
  warnings: string[]
  providerID?: string
  apiKeyEnv?: string
}

type Options = Record<string, any> | undefined

const DEPTHS = ["quick", "normal", "deep"] as const
const DEPTH_FIELDS: Record<string, string> = {
  candidateK: "CANDIDATE_K",
  nResults: "N_RESULTS",
  maxPerEndpoint: "MAX_PER_ENDPOINT",
  snippetLen: "SNIPPET_LEN",
  rawChars: "RAW_CHARS",
}

export function validateBaseURL(value: string): string {
  if (typeof value !== "string") throw new Error("embedding.baseURL must be a string")
  const url = new URL(value)
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error("embedding.baseURL must be an HTTP(S) URL without credentials, query, or fragment")
  }
  return value.replace(/\/+$/, "")
}

export function buildConfig(options: Options): BuiltConfig {
  const env: Record<string, string> = {}
  const warnings: string[] = []
  const o = options ?? {}

  const e = o.embedding ?? {}
  if (typeof e !== "object" || Array.isArray(e)) throw new Error("embedding must be an options object")
  const preset = e.preset ?? "ollama-embeddinggemma2"
  if (!Object.hasOwn(profiles, preset)) throw new Error(`Unknown embedding preset: ${preset}`)
  const profile = profiles[preset as keyof typeof profiles]
  const dimensions = e.dimensions ?? (profile.backend === "ollama" ? o.embeddingDimensions : undefined) ?? profile.dimensions
  if (!Number.isInteger(dimensions) || dimensions < profile.minDimensions || dimensions > profile.dimensions ||
      (profile.allowedDimensions.length && !(profile.allowedDimensions as number[]).includes(dimensions))) {
    throw new Error(`Unsupported embedding dimensions for ${preset}`)
  }
  const model = e.model ?? (profile.backend === "ollama" ? o.embeddingModel : undefined) ?? profile.model
  if (typeof model !== "string" || !model.trim()) throw new Error("embedding.model must be non-empty")
  const contextTokens = e.contextTokens ?? profile.contextTokens
  if (!Number.isInteger(contextTokens) || contextTokens < 1 || contextTokens > profile.contextTokens) {
    throw new Error("embedding.contextTokens must be positive and no greater than the model limit")
  }
  if (o.embeddingScheme && o.embeddingScheme !== profile.scheme) {
    throw new Error("Remove the legacy embeddingScheme override; the preset selects the scheme. Rebuild existing projects.")
  }
  if (o.distanceMetric && o.distanceMetric !== "cosine") throw new Error("Only cosine distance is supported")
  const revision = e.modelRevision ?? ""
  if (profile.backend === "ollama" && revision) throw new Error("Ollama uses its installed model digest; modelRevision is a LiteLLM option")
  if (typeof revision !== "string" || (profile.backend === "litellm" && !revision.trim())) {
    throw new Error("LiteLLM requires embedding.modelRevision; pin the gateway deployment and disable cross-model fallback")
  }
  const timeout = e.timeoutSeconds ?? o.ollamaTimeoutSeconds ?? 120
  if (typeof timeout !== "number" || !Number.isFinite(timeout) || timeout <= 0) throw new Error("embedding.timeoutSeconds must be positive")
  if (e.sendDimensions !== undefined && typeof e.sendDimensions !== "boolean") throw new Error("embedding.sendDimensions must be boolean")
  if (profile.backend !== "ollama" && (e.keepAlive !== undefined || o.ollamaUrl || o.ollamaTimeoutSeconds || o.embeddingModel || o.embeddingDimensions)) {
    throw new Error("Ollama options do not apply to a LiteLLM preset")
  }
  for (const key of ["providerID", "apiKeyEnv"]) {
    if (e[key] !== undefined && (typeof e[key] !== "string" || !e[key].trim())) throw new Error(`embedding.${key} must be non-empty`)
  }
  if (e.apiKey !== undefined) throw new Error("Use embedding.apiKeyEnv or an OpenCode provider connection, not a stored API key")
  if (e.keepAlive !== undefined && typeof e.keepAlive !== "string") throw new Error("embedding.keepAlive must be a string")
  const effective = { preset, model, dimensions, contextTokens, scheme: profile.scheme, revision, normalization: "l2-v1", metric: "cosine" }
  Object.assign(env, {
    JEB_EMBEDDING_PRESET: preset,
    JEB_EMBEDDING_MODEL: model,
    JEB_EMBEDDING_SCHEME: profile.scheme,
    JEB_EMBEDDING_DIMENSIONS: String(dimensions),
    JEB_EMBEDDING_CONTEXT_TOKENS: String(contextTokens),
    JEB_EMBEDDING_REVISION: revision,
    JEB_DISTANCE_METRIC: "cosine",
    JEB_EMBEDDING_TIMEOUT: String(timeout),
    JEB_EMBEDDING_SEND_DIMENSIONS: String(e.sendDimensions ?? true),
    JEB_OLLAMA_KEEP_ALIVE: e.keepAlive ?? "30m",
    // Explicit empties prevent stale shell credentials/headers leaking between providers.
    JEB_EMBEDDING_API_KEY: "",
    JEB_EMBEDDING_HEADERS: "{}",
    JEB_EMBEDDING_BASE_URL: "",
    JEB_OLLAMA_URL: "",
  })
  const baseURL = e.baseURL ?? o.ollamaUrl ?? (profile.backend === "ollama" ? "http://localhost:11434" : undefined)
  if (baseURL !== undefined) env.JEB_EMBEDDING_BASE_URL = validateBaseURL(baseURL)
  if (profile.backend === "litellm" && !baseURL && !e.providerID) throw new Error("LiteLLM needs embedding.providerID or embedding.baseURL")
  if (profile.backend === "ollama" && e.providerID) throw new Error("embedding.providerID is only supported for LiteLLM")

  // --- Query-time (safe) ---
  const maxDistance = o.maxDistance ?? {}
  for (const col of ["graph", "attacks"]) {
    const v = maxDistance[col]
    if (v == null) continue
    const n = Number(v)
    if (Number.isFinite(n) && n >= 0 && n <= 2) env[`JEB_MAX_DISTANCE_${col.toUpperCase()}`] = String(n)
    else warnings.push(`maxDistance.${col} must be a number in [0, 2]; ignoring ${JSON.stringify(v)}.`)
  }

  if (o.candidateCeiling != null) {
    const n = Number(o.candidateCeiling)
    if (Number.isInteger(n) && n > 0) env.JEB_CANDIDATE_CEILING = String(n)
    else warnings.push(`candidateCeiling must be a positive integer; ignoring ${JSON.stringify(o.candidateCeiling)}.`)
  }

  // Embedding batch budget: affects how many embedding round trips an import makes,
  // not the vectors themselves, so it needs no rebuild.
  for (const [key, envName] of [
    ["embedBatchDocs", "JEB_EMBED_BATCH_DOCS"],
    ["embedBatchChars", "JEB_EMBED_BATCH_CHARS"],
  ] as const) {
    if (o[key] == null) continue
    const n = Number(o[key])
    if (Number.isInteger(n) && n > 0) env[envName] = String(n)
    else warnings.push(`${key} must be a positive integer; ignoring ${JSON.stringify(o[key])}.`)
  }

  const depth = o.depth ?? {}
  for (const name of DEPTHS) {
    const preset = depth[name] ?? {}
    for (const [key, suffix] of Object.entries(DEPTH_FIELDS)) {
      const v = preset[key]
      if (v == null) continue
      const n = Number(v)
      if (Number.isInteger(n) && n >= 0) env[`JEB_DEPTH_${name.toUpperCase()}_${suffix}`] = String(n)
      else warnings.push(`depth.${name}.${key} must be a non-negative integer; ignoring ${JSON.stringify(v)}.`)
    }
  }

  const indexSignature = JSON.stringify(effective)
  return { env, indexSignature, warnings, providerID: e.providerID, apiKeyEnv: e.apiKeyEnv }
}
