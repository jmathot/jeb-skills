// Edit only this plugin's entry, preserving unrelated JSONC settings/comments.
import { existsSync, readFileSync, writeFileSync, renameSync, unlinkSync } from "node:fs"
import { join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { parse, modify, applyEdits, printParseErrorCode } from "jsonc-parser"

const [mode, configDir, pluginPath, ...args] = process.argv.slice(2)
const profiles = JSON.parse(readFileSync(new URL("../src/embedding-profiles.json", import.meta.url), "utf8"))
const fields = { "--preset": "preset", "--provider": "providerID", "--base-url": "baseURL", "--model": "model", "--model-revision": "modelRevision", "--api-key-env": "apiKeyEnv" }
const supplied = {}
for (let i = 0; i < args.length; i += 2) {
  if (!fields[args[i]] || !args[i + 1] || args[i + 1].startsWith("--")) throw new Error(`Invalid installer option ${args[i]}`)
  supplied[fields[args[i]]] = args[i + 1]
}
const path = ["opencode.jsonc", "opencode.json"].map((name) => join(configDir, name)).find(existsSync) ?? join(configDir, "opencode.jsonc")
const original = existsSync(path) ? readFileSync(path, "utf8") : '{\n  "$schema": "https://opencode.ai/config.json"\n}\n'
const errors = []
const config = parse(original, errors, { allowTrailingComma: true })
if (errors.length || !config || typeof config !== "object" || Array.isArray(config)) {
  throw new Error(`Invalid OpenCode configuration: ${errors.map((e) => printParseErrorCode(e.error)).join(", ")}`)
}
if (config.plugins !== undefined && !Array.isArray(config.plugins)) throw new Error("OpenCode plugins must be an array")
const plugins = config.plugins ?? []
// Switching between linked and copied installs must update the same entry.
const ownedPaths = new Set([pluginPath, resolve(configDir, "packages/jebediah"), fileURLToPath(new URL("..", import.meta.url))].map((p) => resolve(p)))
const index = plugins.findIndex((entry) => {
  const name = typeof entry === "string" ? entry : entry?.package
  if (typeof name !== "string") return false
  if (name.startsWith("file://")) return ownedPaths.has(resolve(fileURLToPath(name)))
  return (name.startsWith("/") || name.startsWith(".")) && ownedPaths.has(resolve(configDir, name))
})
const previous = index >= 0 && typeof plugins[index] === "object" ? plugins[index].options ?? {} : {}
const changingPreset = supplied.preset && supplied.preset !== previous.embedding?.preset
const embedding = { preset: "ollama-embeddinggemma2", ...(changingPreset ? {} : previous.embedding ?? {}), ...supplied }
const profile = profiles[embedding.preset]
if (!profile) throw new Error("Select one of the three documented embedding presets")
if (profile.backend === "litellm") {
  if (!embedding.modelRevision?.trim()) throw new Error("LiteLLM requires --model-revision for a pinned deployment (no cross-model fallbacks)")
  if (!embedding.baseURL && !embedding.providerID) embedding.providerID = "litellm"
} else if (embedding.providerID || embedding.modelRevision) throw new Error("--provider and --model-revision only apply to LiteLLM")
if (embedding.baseURL) {
  const url = new URL(embedding.baseURL)
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error("Invalid embedding base URL")
}
const options = { ...previous, embedding }
if (changingPreset) {
  for (const key of ["embeddingModel", "embeddingDimensions", "embeddingScheme", "ollamaUrl", "ollamaTimeoutSeconds"]) delete options[key]
}
const entry = { package: pluginPath, options }
let updated = original
if (config.plugins === undefined) updated = applyEdits(updated, modify(updated, ["plugins"], [entry], { formattingOptions: { insertSpaces: true, tabSize: 2 } }))
else updated = applyEdits(updated, modify(updated, ["plugins", index < 0 ? -1 : index], entry, { formattingOptions: { insertSpaces: true, tabSize: 2 } }))
if (mode === "write" && updated !== original) {
  const temp = `${path}.jeb-${process.pid}.tmp`
  try {
    writeFileSync(temp, updated, { mode: 0o600, flag: "wx" })
    if (existsSync(path) && readFileSync(path, "utf8") !== original) throw new Error("Configuration changed during installation; retry")
    renameSync(temp, path)
  } finally {
    if (existsSync(temp)) unlinkSync(temp)
  }
} else if (!["check", "write"].includes(mode)) throw new Error("Expected check or write")
