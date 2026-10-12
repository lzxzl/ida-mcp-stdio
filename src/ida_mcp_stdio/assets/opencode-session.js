// Managed by ida-mcp-stdio: active-session transcript plugin v1.
// Contract: @opencode-ai/plugin's V1 client, verified with OpenCode 1.15.13
// and plugin SDK 1.14.40. This is not the separate @opencode-ai/sdk/v2 API.
import fs from "node:fs/promises";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";

const stateRoot = __IDA_MCP_STATE_ROOT__;
const format = "ida-mcp-stdio/opencode/v1";
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const managedTool = (tool) => typeof tool === "string" && /^(?:mcp__)?ida[-_]mcp[-_]stdio(?:__|_).+$/.test(tool);
const sessionID = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$/.test(value);

async function safePath(target) {
  let current = path.resolve(target);
  for (;;) {
    try {
      const stat = await fs.lstat(current);
      if (stat.isSymbolicLink()) {
        const standardMacAlias = process.platform === "darwin" &&
          ["/tmp", "/var"].includes(current) && await fs.realpath(current) === `/private${current}`;
        if (!standardMacAlias) throw Error("Refusing symlinked transcript path");
      }
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

// Export one function only: OpenCode invokes each exported plugin function.
export const IdaMcpSession = async ({ client, directory }) => {
  const selected = new Set();
  const pending = new Map();
  const diagnostic = async (error) => {
    try {
      await client.app?.log({ body: { service: "ida-mcp-stdio", level: "warn", message: `Transcript correlation unavailable: ${error.message}` } });
    } catch { /* Diagnostics must never break a tool or write to stdout. */ }
  };
  const writeSnapshot = async (id) => {
    // The plugin context supplies V1, even though a separate V2 SDK exists.
    const result = await client.session.messages({ path: { id }, query: { directory } });
    const messages = Array.isArray(result) ? result : result?.data;
    if (!Array.isArray(messages) || messages.some((message) =>
      !object(message) || !object(message.info) || message.info.sessionID !== id ||
      !Array.isArray(message.parts) || message.parts.some((part) => !object(part) || part.sessionID !== id))) {
      throw Error("Malformed or mismatched active-session messages");
    }
    const file = path.join(stateRoot, `${createHash("sha256").update(id).digest("hex")}.json`);
    await safePath(file);
    try {
      const existing = JSON.parse(await fs.readFile(file, "utf8"));
      if (existing.format !== format || existing.session_id !== id) throw Error("Refusing unmanaged session snapshot");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await fs.mkdir(stateRoot, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") await fs.chmod(stateRoot, 0o700);
    await safePath(file);
    const temporary = path.join(stateRoot, `.snapshot-${randomUUID()}`);
    try {
      const handle = await fs.open(temporary, "wx", 0o600);
      try {
        await handle.writeFile(JSON.stringify({ format, session_id: id, messages }) + "\n", "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      await safePath(file);
      await fs.rename(temporary, file);
    } finally {
      await fs.rm(temporary, { force: true });
    }
    return file;
  };
  const refresh = (id) => {
    // Serialize refreshes so a slower request cannot overwrite newer usage.
    const task = (pending.get(id) ?? Promise.resolve()).then(() => writeSnapshot(id));
    const settled = task.catch(() => {});
    pending.set(id, settled);
    settled.finally(() => { if (pending.get(id) === settled) pending.delete(id); });
    return task;
  };
  return {
    "tool.execute.before": async (input, output) => {
      if (!managedTool(input.tool) || !object(output.args)) return;
      // The runtime executes the original object after trigger({ args }).
      // Replacing output.args would attach metadata to a discarded object.
      const args = output.args;
      if (args._meta !== undefined && !object(args._meta)) {
        await diagnostic(Error("Tool _meta must be an object"));
        return;
      }
      const metadata = { ...(args._meta ?? {}) };
      delete metadata.opencode_session_path;
      if (Object.keys(metadata).length) args._meta = metadata;
      else delete args._meta;
      if (!sessionID(input.sessionID)) {
        await diagnostic(Error("Invalid active session identifier"));
        return;
      }
      selected.add(input.sessionID);
      try {
        metadata.opencode_session_path = await refresh(input.sessionID);
        args._meta = metadata;
      } catch (error) { await diagnostic(error); }
    },
    "tool.execute.after": async (input) => {
      if (!managedTool(input.tool) || !selected.has(input.sessionID)) return;
      try { await refresh(input.sessionID); } catch (error) { await diagnostic(error); }
    },
    event: async ({ event }) => {
      if (!["message.updated", "message.removed", "message.part.updated", "message.part.removed", "session.idle", "session.status", "session.updated", "session.compacted", "session.error"].includes(event.type)) return;
      const properties = event.properties ?? {};
      const id = properties.sessionID ?? properties.info?.sessionID ?? properties.part?.sessionID ?? properties.info?.id;
      if (!selected.has(id)) return;
      try { await refresh(id); } catch (error) { await diagnostic(error); }
    },
  };
};
