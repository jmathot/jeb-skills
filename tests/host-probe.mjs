// Test-only bridge: exercises the actual registered tool executors without
// asking a chat model to select tools. Never installed in the user's OpenCode.
// The private OpenCode host supplies the plugin SDK at this bare import.
import { Plugin, Rpc } from "@opencode/plugin"

const Probe = Rpc.define({
  id: "jeb-test",
  methods: {
    tools: {
      input: { type: "object", additionalProperties: false },
      output: { type: "array", items: { type: "string" } },
      errors: {},
    },
    invoke: {
      input: {
        type: "object",
        properties: { name: { type: "string" }, input: { type: "object" }, sessionID: { type: "string" } },
        required: ["name", "input", "sessionID"],
        additionalProperties: false,
      },
      output: { type: "object", properties: { content: { type: "string" } }, required: ["content"] },
      errors: {},
    },
  },
  events: {},
})

export default Plugin.define({
  id: "jeb-test-probe",
  async setup(ctx) {
    await ctx.rpc.register(Probe, {
      tools: async () => (await ctx.tool.list()).filter((t) => t.id.startsWith("jeb_")).map((t) => t.id),
      invoke: async ({ name, input, sessionID }, context) => {
        if (!["jeb_import", "jeb_query", "jeb_visualize"].includes(name)) throw new Error("Not a JEB tool")
        const tool = (await ctx.tool.list()).find((t) => t.id === name)
        if (!tool) throw new Error("JEB tool not registered")
        return tool.execute(input, {
          sessionID, agent: "jebediah", messageID: "msg_jeb_host_smoke", id: "call_jeb_host_smoke",
          signal: context.signal, progress: async () => {},
        })
      },
    })
  },
})
