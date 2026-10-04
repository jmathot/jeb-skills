import { createHash } from "node:crypto"
import { existsSync, readFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

// Resolve the bundled Python engine relative to this plugin file, NOT relative to
// the engagement project's cwd — the agent runs in the capture's project directory,
// while the engine ships inside the plugin package.
const here = dirname(fileURLToPath(import.meta.url))

export const engineDir = resolve(here, "..", "engine")
export const importScript = join(engineDir, "import", "import_project.py")
export const queryScript = join(engineDir, "query", "agent_interface.py")
export const visualizeScript = join(engineDir, "import", "visualize.py")
export const venvDir = join(engineDir, ".venv")
export const requirementFiles = [
  join(engineDir, "requirements.txt"),
  join(engineDir, "requirements-viz.txt"),
]

export function venvPython(): string {
  return process.platform === "win32"
    ? join(venvDir, "Scripts", "python.exe")
    : join(venvDir, "bin", "python")
}

export function hasVenv(): boolean {
  return existsSync(venvPython())
}

// Fingerprint of the dependency manifests; a change forces a reinstall.
export function requirementsHash(): string {
  const hash = createHash("sha256")
  for (const file of requirementFiles) {
    try {
      hash.update(readFileSync(file))
    } catch {
      hash.update(`missing:${file}`)
    }
  }
  return hash.digest("hex")
}
