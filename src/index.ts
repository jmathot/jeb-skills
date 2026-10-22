import { Plugin } from "@opencode/plugin"
import { configureAgent } from "./agent.js"
import { bootstrap } from "./bootstrap.js"
import { buildConfig } from "./config.js"
import { registerTools } from "./tools.js"

export default Plugin.define({
  id: "jebediah",
  async setup(ctx) {
    const config = buildConfig(ctx.options)
    const { indexSignature, warnings } = config
    for (const warning of warnings) console.warn(`[jebediah] ${warning}`)

    // Warn when an index-defining option changed since last load: existing databases
    // embedded under the old profile must be rebuilt (jeb import command=rebuild).
    try {
      const prev = (await ctx.storage.get("indexProfile")) as { signature?: string } | undefined
      if (prev?.signature !== undefined && prev.signature !== indexSignature) {
        console.warn(
          "[jebediah] the embedding profile changed. " +
            "Existing project databases must be rebuilt: run `jeb import` with command=rebuild for each project.",
        )
      }
      await ctx.storage.set("indexProfile", { signature: indexSignature })
    } catch {
      // storage unavailable; skip the drift check.
    }

    // A failed preparation may be retried; successful bootstrap is shared on disk.
    await registerTools(ctx, () => bootstrap(), config)
    await configureAgent(ctx)
  },
})
