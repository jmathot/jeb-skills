import assert from "node:assert/strict"
import { test } from "node:test"
import { mkdtempSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { pathToFileURL } from "node:url"

const load = (name) => import(pathToFileURL(join(process.env.JEB_TS_OUT, name + ".js")).href)
const { buildConfig } = await load("config")
const { embeddingEnv } = await load("connection")
const { withLock, runCommand } = await load("bootstrap")
const { runEngine } = await load("engine")
const { registerTools, engineContent } = await load("tools")

test("all CLI responses are normalized to one JSON object", () => {
  assert.deepEqual(JSON.parse(engineContent({ code: 0, stdout: "Imported 4 observations\n", stderr: "" })), { ok: true, output: "Imported 4 observations" })
  assert.deepEqual(JSON.parse(engineContent({ code: 0, stdout: "", stderr: "" })), { ok: true, output: "" })
  assert.deepEqual(JSON.parse(engineContent({ code: 1, stdout: '{"error":"mismatch"}', stderr: "diagnostic" })), { error: "mismatch", exit_code: 1, stderr: "diagnostic" })
})

test("public provider settings and active API-key connection are resolved per call", async () => {
  let key = "first"
  const ctx = {
    provider: { get: async () => ({ data: { settings: { baseURL: "https://gateway.example/v1" }, headers: { "x-tenant": "test" }, integrationID: "gateway" } }) },
    integration: { connection: { active: async () => ({}), resolve: async () => ({ type: "key", key }) } },
  }
  const config = buildConfig({ embedding: { preset: "litellm-qwen3-embedding-8b", providerID: "litellm", modelRevision: "r1" } })
  const env = await embeddingEnv(ctx, config)
  assert.equal(env.JEB_EMBEDDING_BASE_URL, "https://gateway.example/v1")
  assert.equal(env.JEB_EMBEDDING_API_KEY, "first")
  assert.deepEqual(JSON.parse(env.JEB_EMBEDDING_HEADERS), { "x-tenant": "test" })
  key = "rotated"
  assert.equal((await embeddingEnv(ctx, config)).JEB_EMBEDDING_API_KEY, "rotated")
  assert.equal(config.env.JEB_EMBEDDING_API_KEY, "")
})

test("bootstrap lock serializes and never removes another owner's lock on timeout", async () => {
  const directory = mkdtempSync(join(tmpdir(), "jeb-lock-"))
  const path = join(directory, "lock")
  try {
    const calls = []
    await Promise.all([1, 2].map((i) => withLock(path, async () => {
      calls.push(`start${i}`)
      await new Promise((r) => setTimeout(r, 20))
      calls.push(`end${i}`)
    })))
    assert.deepEqual(calls, ["start1", "end1", "start2", "end2"])
    assert.equal(existsSync(path), false)
    writeFileSync(path, "other-owner")
    await assert.rejects(withLock(path, async () => {}, 10), /owner PID/)
    assert.equal(readFileSync(path, "utf8"), "other-owner")
  } finally { rmSync(directory, { recursive: true, force: true }) }
})

test("command errors clear timeout and engine cancellation cannot report success", async () => {
  await assert.rejects(runCommand("/nonexistent-jeb-python", [], 1000), /ENOENT/)
  const controller = new AbortController()
  const promise = runEngine({ python: process.execPath, script: "-e", argv: ["setInterval(() => {}, 1000)"], cwd: process.cwd(), env: {}, signal: controller.signal })
  controller.abort()
  assert.notEqual((await promise).code, 0)
  await assert.rejects(runEngine({ python: process.execPath, script: "-e", argv: [], cwd: process.cwd(), env: {}, signal: controller.signal }), /abort/i)
})

test("plugin setup is lazy and registers exactly the native tools", async () => {
  const { default: plugin } = await load("index")
  const tools = []
  await plugin.setup({
    options: {}, storage: { get: async () => undefined, set: async () => {} },
    location: { directory: process.cwd() },
    tool: { transform: async (fn) => fn({ namespace() {}, add: (tool) => tools.push(tool) }) },
    agent: { transform: async (fn) => fn({ get: () => undefined }) },
  })
  assert.deepEqual(tools.map((t) => t.name), ["query", "import", "visualize"])
  assert.ok(tools.every((t) => t.options.namespace === "jeb"))
})

test("write permission denial propagates before bootstrap or engine execution", async () => {
  const tools = []
  let bootstrapped = false
  const ctx = {
    location: { directory: process.cwd() },
    tool: { transform: async (fn) => fn({ namespace() {}, add: (tool) => tools.push(tool) }) },
    permission: { assert: async ({ action }) => { if (action === "edit") throw new Error("denied") } },
  }
  await registerTools(ctx, async () => { bootstrapped = true; return "python3" }, buildConfig({}))
  await assert.rejects(tools.find((t) => t.name === "import").execute({ command: "rebuild" }, { signal: new AbortController().signal }), /denied/)
  assert.equal(bootstrapped, false)
})
