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
    params.signal?.throwIfAborted()
    const child = spawn(params.python, [params.script, ...params.argv], {
      cwd: params.cwd,
      env: { ...process.env, ...params.env },
    })

    let stdout = ""
    let stderr = ""

    let killTimer: ReturnType<typeof setTimeout> | undefined
    const onAbort = () => {
      child.kill("SIGTERM")
      killTimer = setTimeout(() => child.kill("SIGKILL"), 3000)
      killTimer.unref()
    }
    if (params.signal) {
      if (params.signal.aborted) onAbort()
      else params.signal.addEventListener("abort", onAbort, { once: true })
    }

    child.stdout.setEncoding("utf8")
    child.stderr.setEncoding("utf8")
    child.stdout.on("data", (chunk) => (stdout += chunk))
    child.stderr.on("data", (chunk) => (stderr += chunk))
    child.on("error", (err) => {
      clearTimeout(killTimer)
      params.signal?.removeEventListener("abort", onAbort)
      reject(err)
    })
    child.on("close", (code, signal) => {
      clearTimeout(killTimer)
      params.signal?.removeEventListener("abort", onAbort)
      resolve({ code: code ?? (signal ? 128 : 1), stdout, stderr })
    })
  })
}
