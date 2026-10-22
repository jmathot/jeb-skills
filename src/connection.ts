import type { Plugin } from "@opencode/plugin"
import { type BuiltConfig, validateBaseURL } from "./config.js"

// Resolve public provider metadata and credentials at tool execution, not setup,
// so rotating a connection does not leave a long-lived stale secret in a closure.
export async function embeddingEnv(ctx: Plugin.Context, config: BuiltConfig): Promise<Record<string, string>> {
  const env = { ...config.env }
  if (config.providerID) {
    const { data: provider } = await ctx.provider.get({ providerID: config.providerID })
    if (provider.activation === "disabled") throw new Error("The embedding provider is disabled")
    const settings = provider.settings ?? {}
    if (!env.JEB_EMBEDDING_BASE_URL && typeof settings.baseURL === "string") {
      env.JEB_EMBEDDING_BASE_URL = validateBaseURL(settings.baseURL)
    }
    env.JEB_EMBEDDING_HEADERS = JSON.stringify(provider.headers ?? {})
    if (typeof settings.apiKey === "string") env.JEB_EMBEDDING_API_KEY = settings.apiKey
    if (!config.apiKeyEnv && !env.JEB_EMBEDDING_API_KEY && provider.integrationID) {
      const active = await ctx.integration.connection.active(provider.integrationID)
      const credential = active ? await ctx.integration.connection.resolve(active) : undefined
      if (credential?.type === "key") env.JEB_EMBEDDING_API_KEY = credential.key
      else if (credential) throw new Error("Embedding gateway requires an API-key connection; OAuth/external credentials are not forwarded")
    }
  }
  if (config.apiKeyEnv) {
    const key = process.env[config.apiKeyEnv]
    if (!key) throw new Error(`Embedding credential environment variable ${config.apiKeyEnv} is unset`)
    env.JEB_EMBEDDING_API_KEY = key
  }
  if (!env.JEB_EMBEDDING_BASE_URL) throw new Error("No embedding endpoint available; configure embedding.baseURL or the provider settings.baseURL")
  return env
}
