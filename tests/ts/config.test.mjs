import assert from "node:assert/strict"
import { test } from "node:test"
import { join } from "node:path"
import { pathToFileURL } from "node:url"

const { buildConfig } = await import(pathToFileURL(join(process.env.JEB_TS_OUT, "config.js")).href)

test("restating a default does not change the index signature", () => {
  const bare = buildConfig({}).indexSignature
  assert.equal(buildConfig({ embeddingModel: "embeddinggemma-2:latest", distanceMetric: "cosine" }).indexSignature, bare)
  assert.notEqual(buildConfig({ embeddingModel: "other:latest" }).indexSignature, bare)
})

test("query-time options never touch the signature", () => {
  const bare = buildConfig({}).indexSignature
  assert.equal(buildConfig({ maxDistance: { graph: 0.4 } }).indexSignature, bare)
})

test("three presets enforce dimensions, revision, and backend-specific options", () => {
  const base = { preset: "litellm-qwen3-embedding-8b", providerID: "litellm", modelRevision: "r1" }
  assert.equal(buildConfig({ embedding: base }).env.JEB_EMBEDDING_DIMENSIONS, "4096")
  assert.throws(() => buildConfig({ embedding: { preset: "unknown" } }), /Unknown/)
  assert.throws(() => buildConfig({ embedding: { ...base, modelRevision: "" } }), /modelRevision/)
  assert.throws(() => buildConfig({ embedding: { ...base, dimensions: 4097 } }), /dimensions/)
  assert.throws(() => buildConfig({ embedding: { ...base, keepAlive: "30m" } }), /Ollama/)
  assert.throws(() => buildConfig({ embedding: { dimensions: 300 } }), /dimensions/)
  assert.throws(() => buildConfig({ embedding: { ...base, baseURL: "https://user:secret@example.com" } }), /credentials/)
  assert.throws(() => buildConfig({ embedding: { timeoutSeconds: 0 } }), /positive/)
  assert.throws(() => buildConfig({ embeddingScheme: "old" }), /legacy/)
})

test("connection settings do not change index identity", () => {
  const embedding = { preset: "litellm-gemini-embedding-2", baseURL: "https://one.example/v1", modelRevision: "r1" }
  const bare = buildConfig({ embedding }).indexSignature
  assert.equal(buildConfig({ embedding: { ...embedding, baseURL: "https://two.example/v1", timeoutSeconds: 5, apiKeyEnv: "SOME_KEY" } }).indexSignature, bare)
  assert.notEqual(buildConfig({ embedding: { ...embedding, dimensions: 768 } }).indexSignature, bare)
})
