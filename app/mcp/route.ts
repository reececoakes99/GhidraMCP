import { createMcpHandler } from "mcp-handler";
import { z } from "zod";

const baseUrl = process.env.GHIDRA_SERVER_URL || "http://127.0.0.1:8080/";
const text = (value: unknown) => ({
  content: [{ type: "text" as const, text: Array.isArray(value) ? value.join("\n") : String(value) }],
});

async function safeGet(endpoint: string, params: Record<string, unknown> = {}) {
  try {
    const url = new URL(endpoint, baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
    }
    const response = await fetch(url, { signal: AbortSignal.timeout(5000), cache: "no-store" });
    const body = await response.text();
    return response.ok ? body.split(/\r?\n/) : [`Error ${response.status}: ${body.trim()}`];
  } catch (error) {
    return [`Request failed: ${error instanceof Error ? error.message : String(error)}`];
  }
}

async function safePost(endpoint: string, data: Record<string, unknown> | string) {
  try {
    const url = new URL(endpoint, baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
    const isText = typeof data === "string";
    const body = isText
      ? data
      : new URLSearchParams(Object.entries(data).map(([key, value]) => [key, String(value)])).toString();
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": isText ? "text/plain; charset=utf-8" : "application/x-www-form-urlencoded" },
      body,
      signal: AbortSignal.timeout(5000),
      cache: "no-store",
    });
    const result = (await response.text()).trim();
    return response.ok ? result : `Error ${response.status}: ${result}`;
  } catch (error) {
    return `Request failed: ${error instanceof Error ? error.message : String(error)}`;
  }
}

const offset = z.number().int().nonnegative().default(0).describe("Pagination offset");
const limit100 = z.number().int().positive().default(100).describe("Maximum results to return");
const address = z.string().describe("Address in hexadecimal format");

const handler = createMcpHandler(
  async (server) => {
    server.tool("list_methods", "List all function names in the program with pagination.", { offset, limit: limit100 }, async (a) => text(await safeGet("methods", a)));
    server.tool("list_classes", "List all namespace/class names in the program with pagination.", { offset, limit: limit100 }, async (a) => text(await safeGet("classes", a)));
    server.tool("decompile_function", "Decompile a specific function by name and return the decompiled C code.", { name: z.string().describe("Function name") }, async ({ name }) => text(await safePost("decompile", name)));
    server.tool("rename_function", "Rename a function by its current name.", { old_name: z.string(), new_name: z.string() }, async ({ old_name, new_name }) => text(await safePost("renameFunction", { oldName: old_name, newName: new_name })));
    server.tool("rename_data", "Rename a data label at the specified address.", { address, new_name: z.string() }, async ({ address, new_name }) => text(await safePost("renameData", { address, newName: new_name })));
    server.tool("list_segments", "List all memory segments in the program with pagination.", { offset, limit: limit100 }, async (a) => text(await safeGet("segments", a)));
    server.tool("list_imports", "List imported symbols in the program with pagination.", { offset, limit: limit100 }, async (a) => text(await safeGet("imports", a)));
    server.tool("list_exports", "List exported functions or symbols with pagination.", { offset, limit: limit100 }, async (a) => text(await safeGet("exports", a)));
    server.tool("list_namespaces", "List all non-global namespaces in the program with pagination.", { offset, limit: limit100 }, async (a) => text(await safeGet("namespaces", a)));
    server.tool("list_data_items", "List defined data labels and values with pagination.", { offset, limit: limit100 }, async (a) => text(await safeGet("data", a)));
    server.tool("search_functions_by_name", "Search for functions whose name contains a substring.", { query: z.string().min(1), offset, limit: limit100 }, async (a) => text(await safeGet("searchFunctions", a)));
    server.tool("rename_variable", "Rename a local variable within a function.", { function_name: z.string(), old_name: z.string(), new_name: z.string() }, async (a) => text(await safePost("renameVariable", { functionName: a.function_name, oldName: a.old_name, newName: a.new_name })));
    server.tool("get_function_by_address", "Get a function by its address.", { address }, async (a) => text(await safeGet("get_function_by_address", a)));
    server.tool("get_current_address", "Get the address currently selected by the Ghidra user.", {}, async () => text(await safeGet("get_current_address")));
    server.tool("get_current_function", "Get the function currently selected by the Ghidra user.", {}, async () => text(await safeGet("get_current_function")));
    server.tool("list_functions", "List all functions in the Ghidra database.", {}, async () => text(await safeGet("list_functions")));
    server.tool("decompile_function_by_address", "Decompile a function at the given address.", { address }, async (a) => text(await safeGet("decompile_function", a)));
    server.tool("disassemble_function", "Get assembly code for a function.", { address }, async (a) => text(await safeGet("disassemble_function", a)));
    server.tool("set_decompiler_comment", "Set a comment at an address in function pseudocode.", { address, comment: z.string() }, async (a) => text(await safePost("set_decompiler_comment", a)));
    server.tool("set_disassembly_comment", "Set a comment at an address in function disassembly.", { address, comment: z.string() }, async (a) => text(await safePost("set_disassembly_comment", a)));
    server.tool("rename_function_by_address", "Rename a function by its address.", { function_address: address, new_name: z.string() }, async (a) => text(await safePost("rename_function_by_address", a)));
    server.tool("set_function_prototype", "Set a function prototype.", { function_address: address, prototype: z.string() }, async (a) => text(await safePost("set_function_prototype", a)));
    server.tool("set_local_variable_type", "Set a local variable type.", { function_address: address, variable_name: z.string(), new_type: z.string() }, async (a) => text(await safePost("set_local_variable_type", a)));
    server.tool("get_xrefs_to", "Get all references to an address.", { address, offset, limit: limit100 }, async (a) => text(await safeGet("xrefs_to", a)));
    server.tool("get_xrefs_from", "Get all references from an address.", { address, offset, limit: limit100 }, async (a) => text(await safeGet("xrefs_from", a)));
    server.tool("get_function_xrefs", "Get all references to a function by name.", { name: z.string(), offset, limit: limit100 }, async (a) => text(await safeGet("function_xrefs", a)));
    server.tool("list_strings", "List defined strings and their addresses.", { offset, limit: z.number().int().positive().default(2000), filter: z.string().optional() }, async (a) => text(await safeGet("strings", a)));
  },
  {},
  { basePath: "", verboseLogs: true, maxDuration: 60, disableSse: true },
);

export { handler as GET, handler as POST, handler as DELETE };
