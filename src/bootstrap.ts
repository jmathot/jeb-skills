import { spawn } from "node:child_process"
import { closeSync, openSync, unlinkSync, writeSync } from "node:fs"
import type { Plugin } from "@opencode/plugin"
import { INDEX_DEFAULTS } from "./config.js"
import { hasVenv, requirementFiles, requirementsHash, venvDir, venvPython } from "./paths.js"

interface StoredBootstrap {
  reqHash?: string
}

const PIP_TIMEOUT_MS = 10 * 60 * 1000
const LOCK_WAIT_MS = 5 * 60 * 1000

function run(command: string, args: string[], timeoutMs = PIP_TIMEOUT_MS): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] })
    const timer = setTimeout(() => {
      child.kill("SIGKILL")
      reject(new Error(`${command} timed out after ${Math.round(timeoutMs / 1000)}s`))
    }, timeoutMs)
    child.on("close", () => clearTimeout(timer))
    let stderr = ""
    child.stderr.on("data", (chunk) => (stderr += chunk))
    child.on("error", reject)
    child.on("close", (code) =>
      code === 0 ? resolve() : reject(new Error(`${command} exited ${code}: ${stderr.trim()}`)),
    )
  })
}

// Serialises venv creation across concurrent plugin loads (several OpenCode
// windows can start at once). A lock older than the wait limit is taken over.
async function withLock<T>(path: string, work: () => Promise<T>): Promise<T> {
  const started = Date.now()
  for (;;) {
    try {
      const fd = openSync(path, "wx")
      writeSync(fd, String(process.pid))
      closeSync(fd)
      break
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err
      if (Date.now() - started > LOCK_WAIT_MS) {
        try {
          unlinkSync(path)
        } catch {}
        continue
      }
      await new Promise((r) => setTimeout(r, 500))
    }
  }
  try {
    return await work()
  } finally {
    try {
      unlinkSync(path)
    } catch {}
  }
}

// Ensure the engine venv exists with current dependencies. Idempotent: gated on a
// hash of the requirement files cached in plugin storage, so a warm load is a no-op.
// Failure is logged but non-fatal — the plugin still loads and tools surface the
// real error if used before the environment is ready.
export async function bootstrap(ctx: Plugin.Context, pythonBin = "python3"): Promise<string> {
  const python = venvPython()
  const reqHash = requirementsHash()

  let stored: StoredBootstrap | undefined
  try {
    stored = (await ctx.storage.get("bootstrap")) as StoredBootstrap | undefined
  } catch {
    stored = undefined
  }

  if (hasVenv() && stored?.reqHash === reqHash) {
    await warnIfOllamaMissing(ctx.options)
    return python
  }

  try {
    await withLock(`${venvDir}.lock`, async () => {
      if (!hasVenv()) {
        console.log("[jebediah] creating Python engine venv…")
        await run(pythonBin, ["-m", "venv", venvDir])
      }
      console.log("[jebediah] installing engine dependencies (first run only)…")
      await run(python, ["-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-r", requirementFiles[0], "-r", requirementFiles[1]])
      await ctx.storage.set("bootstrap", { reqHash })
      console.log("[jebediah] engine ready.")
    })
  } catch (err) {
    console.error(
      `[jebediah] engine bootstrap failed (${(err as Error).message}). ` +
        `Create it manually: python3 -m venv '${venvDir}' && '${python}' -m pip install -r '${requirementFiles[0]}' -r '${requirementFiles[1]}'`,
    )
  }

  await warnIfOllamaMissing(ctx.options)
  return python
}

async function warnIfOllamaMissing(options: Record<string, any> | undefined): Promise<void> {
  const model = (options?.embeddingModel as string) || INDEX_DEFAULTS.embeddingModel
  const wanted = model.includes(":") ? model : `${model}:latest`
  const base = new URL((options?.ollamaUrl as string) || INDEX_DEFAULTS.ollamaUrl).origin
  try {
    const response = await fetch(`${base}/api/tags`, { signal: AbortSignal.timeout(3000) })
    const tags = (await response.json()) as { models?: { name?: string }[] }
    if (!(tags.models ?? []).some((m) => m.name === wanted)) {
      console.warn(`[jebediah] Ollama model '${wanted}' not found. Run: ollama pull ${wanted}`)
    }
  } catch {
    console.warn(`[jebediah] could not reach Ollama at ${base}. Imports/queries need a running Ollama with the embedding model pulled.`)
  }
}
