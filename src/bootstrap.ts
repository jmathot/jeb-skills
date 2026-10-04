import { spawn } from "node:child_process"
import type { Plugin } from "@opencode/plugin"
import { hasVenv, requirementFiles, requirementsHash, venvDir, venvPython } from "./paths.js"

interface StoredBootstrap {
  reqHash?: string
}

function run(command: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] })
    let stderr = ""
    child.stderr.on("data", (chunk) => (stderr += chunk))
    child.on("error", reject)
    child.on("close", (code) =>
      code === 0 ? resolve() : reject(new Error(`${command} exited ${code}: ${stderr.trim()}`)),
    )
  })
}

function capture(command: string, args: string[]): Promise<{ code: number; stdout: string }> {
  return new Promise((resolve) => {
    const child = spawn(command, args)
    let stdout = ""
    child.stdout.on("data", (chunk) => (stdout += chunk))
    child.on("error", () => resolve({ code: -1, stdout: "" }))
    child.on("close", (code) => resolve({ code: code ?? 0, stdout }))
  })
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
    if (!hasVenv()) {
      console.log("[jebediah] creating Python engine venv…")
      await run(pythonBin, ["-m", "venv", venvDir])
    }
    console.log("[jebediah] installing engine dependencies (first run only)…")
    await run(python, ["-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-r", requirementFiles[0], "-r", requirementFiles[1]])
    await ctx.storage.set("bootstrap", { reqHash })
    console.log("[jebediah] engine ready.")
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
  const model = (options?.embeddingModel as string) || "embeddinggemma:latest"
  const base = model.split(":")[0]
  const { code, stdout } = await capture("ollama", ["list"])
  if (code !== 0) {
    console.warn("[jebediah] could not reach Ollama (`ollama list` failed). Imports/queries need a running Ollama with the embedding model pulled.")
    return
  }
  if (!stdout.includes(base)) {
    console.warn(`[jebediah] Ollama model '${model}' not found. Run: ollama pull ${model}`)
  }
}
