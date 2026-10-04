import { Plugin } from "@opencode/plugin"
import { configureAgent } from "./agent.js"
import { bootstrap } from "./bootstrap.js"
import { buildConfig } from "./config.js"
import { registerTools } from "./tools.js"

export default Plugin.define({
  id: "jebediah",
  async setup(ctx) {
    const { env, indexSignature, warnings } = buildConfig(ctx.options)
    for (const warning of warnings) console.warn(`[jebediah] ${warning}`)

    // Warn when an index-defining option changed since last load: existing databases
    // embedded under the old profile must be rebuilt (jeb import command=rebuild).
    try {
      const prev = (await ctx.storage.get("indexProfile")) as { signature?: string } | undefined
      if (prev?.signature !== undefined && prev.signature !== indexSignature) {
        console.warn(
          "[jebediah] an index-defining option (embedding model/dimensions/scheme, distance metric, or ollama URL) changed. " +
            "Existing project databases must be rebuilt: run `jeb import` with command=rebuild for each project.",
        )
      }
      await ctx.storage.set("indexProfile", { signature: indexSignature })
    } catch {
      // storage unavailable; skip the drift check.
    }

    const python = await bootstrap(ctx)
    await registerTools(ctx, python, env)
    await configureAgent(ctx)
  },
})
