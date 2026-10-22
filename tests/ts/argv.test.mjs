// buildArgv: the one place user input becomes engine argv. Run by tests/run.sh
// (tier U) after compiling src/ with tsc: node --test tests/ts/argv.test.mjs <outdir>
import assert from "node:assert/strict"
import { test } from "node:test"
import { join } from "node:path"
import { pathToFileURL } from "node:url"

const outDir = process.env.JEB_TS_OUT
const { buildArgv, resolveDbPath } = await import(pathToFileURL(join(outDir, "tools.js")).href)

test("dash-prefixed positional goes behind --", () => {
  const argv = buildArgv({ command: "get", target: "--delete-everything" }, { positionals: ["target"], allowed: ["target", "collection"] })
  assert.deepEqual(argv, ["--", "--delete-everything"])
})

test("fields that do not apply to the command are rejected", () => {
  assert.throws(
    () => buildArgv({ command: "get", target: "x", limit: 5 }, { positionals: ["target"], allowed: ["target"] }),
    /does not apply to command "get"/,
  )
})

test("array values repeat the flag", () => {
  const argv = buildArgv(
    { command: "endpoint", target: "/a", method: ["GET", "POST"] },
    { positionals: ["target"], allowed: ["target", "method"] },
  )
  assert.deepEqual(argv, ["--method", "GET", "--method", "POST", "--", "/a"])
})

test("booleans become bare flags, false is omitted, paired flags pick a side", () => {
  const opts = { positionals: [], paired: { auto_detect: ["--yes", "--no"] } }
  assert.deepEqual(buildArgv({ command: "x", include_static: true, cors_open: false }, opts), ["--include-static"])
  assert.deepEqual(buildArgv({ command: "x", auto_detect: false }, opts), ["--no"])
  assert.deepEqual(buildArgv({ command: "x", auto_detect: true }, opts), ["--yes"])
})

test("empty values are skipped and overrides rename flags", () => {
  const argv = buildArgv(
    { command: "search", target: "q", collection: "graph", limit: "", where: undefined },
    { positionals: ["target"], flagOverrides: { collection: "--in" } },
  )
  assert.deepEqual(argv, ["--in", "graph", "--", "q"])
})

test("project_dir becomes db_path under chroma_db", () => {
  assert.deepEqual(resolveDbPath({ command: "map", project_dir: "/work/eng" }), { command: "map", db_path: "/work/eng/chroma_db" })
  assert.deepEqual(resolveDbPath({ command: "map" }), { command: "map" })
  assert.throws(() => resolveDbPath({ command: "map", project_dir: "/a", db_path: "/b" }), /either project_dir or db_path/)
})
