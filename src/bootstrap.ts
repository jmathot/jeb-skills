import { spawn } from "node:child_process"
import { closeSync, openSync, readFileSync, unlinkSync, writeFileSync, writeSync } from "node:fs"
import { join } from "node:path"
import { hasVenv, requirementFiles, requirementsHash, venvDir, venvPython } from "./paths.js"

const PIP_TIMEOUT_MS = 10 * 60 * 1000

export function runCommand(command: string, args: string[], timeoutMs = PIP_TIMEOUT_MS): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "ignore", "pipe"] })
    const timer = setTimeout(() => {
      child.kill("SIGKILL")
      reject(new Error(`${command} timed out`))
    }, timeoutMs)
    let stderr = ""
    child.stderr.on("data", (chunk) => (stderr = (stderr + chunk).slice(-8000)))
    child.on("error", (err) => { clearTimeout(timer); reject(err) })
    child.on("close", (code) => {
      clearTimeout(timer)
      code === 0 ? resolve() : reject(new Error(`${command} exited ${code}: ${stderr.trim()}`))
    })
  })
}

// Never steal a lock merely because installation is slow. A failed owner leaves
// its PID for diagnosis; stale locks are removed manually after checking that PID.
export async function withLock<T>(path: string, work: () => Promise<T>, waitMs = 12 * 60 * 1000): Promise<T> {
  const started = Date.now()
  for (;;) {
    try {
      const fd = openSync(path, "wx")
      try { writeSync(fd, String(process.pid)) } finally { closeSync(fd) }
      break
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err
      if (Date.now() - started >= waitMs) throw new Error(`Timed out waiting for ${path}; check its owner PID before removing a stale lock`)
      await new Promise((r) => setTimeout(r, Math.min(100, waitMs)))
    }
  }
  try {
    return await work()
  } finally {
    unlinkSync(path)
  }
}

// Shared disk stamp, checked again under the lock. No model probing or downloads
// at startup. This runs lazily on first tool use, not on every project load.
export async function bootstrap(pythonBin = "python3"): Promise<string> {
  const python = venvPython()
  const reqHash = requirementsHash()
  const stamp = join(venvDir, ".jeb-requirements")
  const ready = () => {
    try { return hasVenv() && readFileSync(stamp, "utf8") === reqHash } catch { return false }
  }
  if (ready()) return python
  await withLock(`${venvDir}.lock`, async () => {
    if (ready()) return
    if (!hasVenv()) {
      await runCommand(pythonBin, ["-c", "import sys; assert sys.version_info >= (3, 10), 'Python 3.10+ required'"])
      await runCommand(pythonBin, ["-m", "venv", venvDir])
    }
    console.log("[jebediah] installing Python engine dependencies…")
    await runCommand(python, ["-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-r", requirementFiles[0], "-r", requirementFiles[1]])
    writeFileSync(stamp, reqHash)
  })
  return python
}
