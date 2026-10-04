import type { Plugin } from "@opencode/plugin"

// A plugin cannot create a primary agent (the AgentEditor only lists/updates/removes
// existing ones), so the J.E.B.E.D.I.A.H. persona ships as agents/jebediah.md, which
// the user installs alongside the plugin. When that agent is present we keep its
// one-line description in sync from here; otherwise this is a no-op.
const DESCRIPTION =
  "Web app pentesting over an imported Burp Suite capture — maps the site, investigates endpoints, hunts vulnerabilities from structural evidence, and records findings via the jeb_* tools."

export async function configureAgent(ctx: Plugin.Context): Promise<void> {
  try {
    await ctx.agent.transform((editor) => {
      if (!editor.get("jebediah")) return
      editor.update("jebediah", (agent) => {
        if (!agent.description) agent.description = DESCRIPTION
      })
    })
  } catch {
    // Agent not loaded yet or transform unsupported — the markdown definition stands on its own.
  }
}
