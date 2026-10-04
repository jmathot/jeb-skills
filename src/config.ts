// Translate opencode.json plugin `options` into the JEB_* environment variables the
// Python engine reads. Two tiers:
//   - query-time knobs: safe to change anytime (distance cutoffs, depth presets,
//     candidate ceiling).
//   - index-defining knobs: embedding model/dimensions/scheme, distance metric,
//     ollama URL. Changing these changes the recorded embedding profile, so queries
//     against an existing database will fail until it is rebuilt (jeb_rebuild). We
//     fold them into `indexSignature` so setup() can warn when one changes.

export interface BuiltConfig {
  env: Record<string, string>
  indexSignature: string
  warnings: string[]
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

export function buildConfig(options: Options): BuiltConfig {
  const env: Record<string, string> = {}
  const warnings: string[] = []
  const o = options ?? {}

  // --- Index-defining (rebuild-affecting) ---
  const indexParts: string[] = []
  const setIndex = (key: string, envName: string, value: unknown, cast = String) => {
    if (value === undefined || value === null || value === "") return
    env[envName] = cast(value)
    indexParts.push(`${key}=${env[envName]}`)
  }
  setIndex("embeddingModel", "JEB_EMBEDDING_MODEL", o.embeddingModel)
  setIndex("embeddingScheme", "JEB_EMBEDDING_SCHEME", o.embeddingScheme)
  setIndex("distanceMetric", "JEB_DISTANCE_METRIC", o.distanceMetric)
  setIndex("ollamaUrl", "JEB_OLLAMA_URL", o.ollamaUrl)
  if (Number.isInteger(o.embeddingDimensions)) {
    setIndex("embeddingDimensions", "JEB_EMBEDDING_DIMENSIONS", o.embeddingDimensions)
  } else if (o.embeddingDimensions != null) {
    warnings.push(`embeddingDimensions must be an integer; ignoring ${JSON.stringify(o.embeddingDimensions)}.`)
  }

  // ollamaTimeoutSeconds is runtime-only, not part of the index profile.
  if (o.ollamaTimeoutSeconds != null) {
    const n = Number(o.ollamaTimeoutSeconds)
    if (Number.isFinite(n) && n > 0) env.JEB_OLLAMA_TIMEOUT = String(Math.trunc(n))
    else warnings.push(`ollamaTimeoutSeconds must be a positive number; ignoring ${JSON.stringify(o.ollamaTimeoutSeconds)}.`)
  }

  // --- Query-time (safe) ---
  const maxDistance = o.maxDistance ?? {}
  for (const col of ["structure", "behavior", "attacks"]) {
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

  return { env, indexSignature: indexParts.sort().join("|"), warnings }
}
