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
