import { spawn } from "node:child_process"

export interface RunResult {
  code: number
  stdout: string
  stderr: string
}

export interface RunParams {
  python: string
  script: string
  argv: string[]
  cwd: string
  env: Record<string, string>
  signal?: AbortSignal
}

// Spawn the engine CLI and collect its output. The Python entrypoints already emit
// one JSON object on stdout (and a JSON error + nonzero exit on failure), so callers
// forward stdout verbatim. The tool's AbortSignal kills the child on cancellation.
export function runEngine(params: RunParams): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(params.python, [params.script, ...params.argv], {
      cwd: params.cwd,
      env: { ...process.env, ...params.env },
    })

    let stdout = ""
    let stderr = ""

    const onAbort = () => child.kill("SIGTERM")
    if (params.signal) {
      if (params.signal.aborted) onAbort()
      else params.signal.addEventListener("abort", onAbort, { once: true })
    }

    child.stdout.on("data", (chunk) => (stdout += chunk))
    child.stderr.on("data", (chunk) => (stderr += chunk))
    child.on("error", (err) => {
      params.signal?.removeEventListener("abort", onAbort)
      reject(err)
    })
    child.on("close", (code) => {
      params.signal?.removeEventListener("abort", onAbort)
      resolve({ code: code ?? 0, stdout, stderr })
    })
  })
}
