import { z } from "zod";
import { JsonValueSchema, type JsonObject, type JsonValue } from "../intent/JsonValue.js";

/**
 * `agent-safe.profile.mcp/1`: an MCP server's consequential tools described as
 * data. Each tool names the action it becomes, the target it acts on (a
 * template over its arguments), the argument that names its subject (the
 * customer it is for), the arguments that decide what it does, and the
 * arguments it accepts. A guard reads the file in place of a binding written
 * in code, so governing a tool is a reviewable file, not code reached by name.
 */
export const MCP_PROFILE_CONTRACT = "agent-safe.profile.mcp/1";

export const MCP_PROFILE_SCHEMA_ID =
  "https://github.com/decionis/agent-safe-pipeline/blob/master/spec/profiles/mcp/v1/schema.json";

/** The most arguments a tool declares, and the most placeholders its target holds. */
export const MAX_TOOL_ARGUMENTS = 64;
export const MAX_TARGET_PLACEHOLDERS = 16;

/** The types an argument may be declared as; a scalar one may fill a target or name a subject. */
export const MCP_ARGUMENT_TYPES = [
  "string",
  "number",
  "integer",
  "boolean",
  "array",
  "object",
] as const;
export type McpArgumentType = (typeof MCP_ARGUMENT_TYPES)[number];

/** An argument's name starts with a letter, so no declared name can be `__proto__`. */
const argumentName = z.string().regex(/^[a-z]\w{0,63}$/i);
const text = (max: number) => z.string().trim().min(1).max(max);

export const McpArgumentSchema = z.strictObject({
  type: z.enum(MCP_ARGUMENT_TYPES),
  /** Absent means optional: a call may leave the argument out. */
  required: z.boolean().optional(),
  /** The longest a string argument may be; a string only. */
  maxLength: z.number().int().min(1).max(100_000).optional(),
});

export const McpToolSchema = z.strictObject({
  /** The tool as the server publishes it. */
  tool: z
    .string()
    .min(1)
    .max(200)
    .regex(/^[a-z0-9][\w.:/-]*$/i),
  /** The intent's action type. */
  action: z
    .string()
    .max(120)
    .regex(/^[a-z][a-z0-9._:-]*$/),
  /** The operation in the downstream system, for the intent's downstream target. */
  operation: text(200),
  summary: text(300),
  /** `crm:customer:{customerId}`: every placeholder a required scalar argument. */
  target: z.string().min(1).max(500),
  /** The argument naming the tool's subject, when the tool acts for one party. */
  subject: argumentName.optional(),
  /** The arguments that decide what the tool does, for evidence and an approval screen. */
  consequential: z.array(argumentName).max(MAX_TOOL_ARGUMENTS),
  /** Every argument the tool accepts; any other is refused, never dropped. */
  arguments: z.record(argumentName, McpArgumentSchema),
});

export const McpProfileDefinitionSchema = z.strictObject({
  profile: z.literal(MCP_PROFILE_CONTRACT),
  /** `<system>/<server>/<version>`, for example `crm/mcp/v1`. */
  id: z
    .string()
    .regex(/^[a-z][a-z0-9]*\/[a-z][a-z0-9]*\/v\d+(\.\d+)?$/)
    .max(120),
  title: text(200),
  /** The system the tools' effects land in: the intent's downstream system. */
  system: text(200),
  environment: text(200).optional(),
  tools: z.array(McpToolSchema).min(1).max(200),
});

export type McpArgumentDefinition = z.infer<typeof McpArgumentSchema>;
export type McpToolDefinition = z.infer<typeof McpToolSchema>;
export type McpProfileDefinition = z.infer<typeof McpProfileDefinitionSchema>;

/** A subject check's answer for a tool call: `MATCH`, or why it is refused. */
export type McpSubjectCheck = "MATCH" | "SUBJECT_ABSENT" | "SUBJECT_MISMATCH";

export class McpProfileError extends Error {
  public constructor(
    public readonly code: "MCP_PROFILE_INVALID",
    public readonly detail: string,
  ) {
    super(code);
    this.name = "McpProfileError";
  }
}

const SCALAR: ReadonlySet<McpArgumentType> = new Set(["string", "number", "integer", "boolean"]);
const SUBJECT_TYPES: ReadonlySet<McpArgumentType> = new Set(["string", "number", "integer"]);
/** The longest subject: an identifier, never a payload. */
const MAX_SUBJECT_LENGTH = 200;

/**
 * One MCP tool profile, validated. Every rule a schema cannot state is held
 * here, at parse: a tool named twice, two tools on one action, a target that
 * names an argument a call
 * could leave out, a subject that is not a required identifier, a
 * consequential argument the tool does not accept.
 */
export class McpToolProfile {
  private readonly byName: ReadonlyMap<string, McpToolDefinition>;
  private readonly schemas = new Map<string, z.ZodType<JsonObject>>();

  private constructor(public readonly definition: McpProfileDefinition) {
    const byName = new Map<string, McpToolDefinition>();
    const actions = new Set<string>();
    for (const tool of definition.tools) {
      if (byName.has(tool.tool))
        throw new McpProfileError("MCP_PROFILE_INVALID", `duplicate tool ${tool.tool}`);
      // A grant authorizes an action, and the guard dispatches the one tool
      // registered under it: two tools on one action would be ambiguous.
      if (actions.has(tool.action))
        throw new McpProfileError("MCP_PROFILE_INVALID", `tool ${tool.tool} repeats an action`);
      actions.add(tool.action);
      McpToolProfile.rules(tool);
      byName.set(tool.tool, tool);
    }
    this.byName = byName;
  }

  /** Validates a definition (closed schema, the rules above) and compiles it. */
  public static parse(value: unknown): McpToolProfile {
    const parsed = McpProfileDefinitionSchema.safeParse(value);
    if (!parsed.success)
      throw new McpProfileError(
        "MCP_PROFILE_INVALID",
        parsed.error.issues
          .slice(0, 3)
          .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
          .join("; "),
      );
    return new McpToolProfile(parsed.data);
  }

  public get id(): string {
    return this.definition.id;
  }

  /** Every tool the profile governs, in profile order. */
  public tools(): readonly string[] {
    return this.definition.tools.map((tool) => tool.tool);
  }

  public tool(name: string): McpToolDefinition | null {
    return this.byName.get(name) ?? null;
  }

  /**
   * The arguments a tool accepts, as a closed validator: each declared one of
   * its type, a required one present, any other refused. A number is finite;
   * an integer is whole; an array or object holds JSON.
   */
  public argumentsSchema(name: string): z.ZodType<JsonObject> {
    const cached = this.schemas.get(name);
    if (cached !== undefined) return cached;
    const tool = this.byName.get(name);
    if (tool === undefined) throw new McpProfileError("MCP_PROFILE_INVALID", `no tool ${name}`);
    const shape: Record<string, z.ZodType> = {};
    for (const [argument, declared] of Object.entries(tool.arguments)) {
      const base = McpToolProfile.validator(declared);
      shape[argument] = declared.required === true ? base : base.optional();
    }
    const schema = z.strictObject(shape) as unknown as z.ZodType<JsonObject>;
    this.schemas.set(name, schema);
    return schema;
  }

  /**
   * The subject a call names, when its tool names a subject argument: a
   * string or a finite number, as a string, of 1 to 200 characters; null when
   * the argument holds neither. Undefined when the tool names no subject.
   */
  public static subjectOf(tool: McpToolDefinition, args: JsonObject): string | null | undefined {
    if (tool.subject === undefined) return undefined;
    const value: JsonValue | undefined = Object.hasOwn(args, tool.subject)
      ? args[tool.subject]
      : undefined;
    const named =
      typeof value === "string"
        ? value
        : typeof value === "number" && Number.isFinite(value)
          ? String(value)
          : null;
    return named === null || named.length === 0 || named.length > MAX_SUBJECT_LENGTH ? null : named;
  }

  /** A call's subject against the session's, as `agent-safe.profile.api/1` checks a read's. */
  public static checkSubject(
    tool: McpToolDefinition,
    args: JsonObject,
    subject: string,
  ): McpSubjectCheck {
    const named = McpToolProfile.subjectOf(tool, args);
    if (named === undefined) return "MATCH";
    if (named === null) return "SUBJECT_ABSENT";
    return named === subject ? "MATCH" : "SUBJECT_MISMATCH";
  }

  private static validator(declared: McpArgumentDefinition): z.ZodType {
    switch (declared.type) {
      case "string":
        return declared.maxLength === undefined ? z.string() : z.string().max(declared.maxLength);
      case "number":
        return z.number().finite();
      case "integer":
        return z.number().int();
      case "boolean":
        return z.boolean();
      case "array":
        return z.array(JsonValueSchema);
      case "object":
        return z.record(z.string(), JsonValueSchema);
    }
  }

  private static rules(tool: McpToolDefinition): void {
    const refuse = (detail: string): never => {
      throw new McpProfileError("MCP_PROFILE_INVALID", `tool ${tool.tool} ${detail}`);
    };
    const declared = Object.entries(tool.arguments);
    if (declared.length > MAX_TOOL_ARGUMENTS) refuse("declares too many arguments");
    for (const [name, argument] of declared) {
      if (argument.maxLength !== undefined && argument.type !== "string")
        refuse(`bounds the length of ${name}, which is not a string`);
    }
    const required = (name: string, types: ReadonlySet<McpArgumentType>): boolean => {
      const argument = tool.arguments[name];
      return (
        Object.hasOwn(tool.arguments, name) &&
        argument !== undefined &&
        argument.required === true &&
        types.has(argument.type)
      );
    };
    const placeholders = McpToolProfile.placeholders(tool.target);
    if (placeholders === null) refuse("has a malformed target");
    for (const name of placeholders ?? []) {
      if (!required(name, SCALAR)) refuse(`fills its target from ${name}, not a required scalar`);
    }
    if (tool.subject !== undefined && !required(tool.subject, SUBJECT_TYPES))
      refuse(`names ${tool.subject} as its subject, not a required string or number`);
    if (new Set(tool.consequential).size !== tool.consequential.length)
      refuse("names a consequential argument twice");
    for (const name of tool.consequential) {
      if (!Object.hasOwn(tool.arguments, name)) refuse(`names ${name} consequential, not accepted`);
    }
  }

  /** A target's placeholder names, by one linear scan; null when a brace is unbalanced or empty. */
  private static placeholders(target: string): string[] | null {
    const names: string[] = [];
    for (let at = 0; at < target.length; at += 1) {
      const character = target[at];
      if (character === "}") return null;
      if (character !== "{") continue;
      const close = target.indexOf("}", at + 1);
      if (close === -1) return null;
      const name = target.slice(at + 1, close);
      if (name.length === 0 || name.includes("{")) return null;
      names.push(name);
      if (names.length > MAX_TARGET_PLACEHOLDERS) return null;
      at = close;
    }
    return names;
  }
}

/** The published JSON Schema of an MCP tool profile, generated from the validator above. */
export function mcpProfileJsonSchema(): Record<string, unknown> {
  const generated = z.toJSONSchema(McpProfileDefinitionSchema, {
    target: "draft-2020-12",
    io: "input",
  });
  const schema: Record<string, unknown> = { ...generated };
  delete schema["$schema"];
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: MCP_PROFILE_SCHEMA_ID,
    title: MCP_PROFILE_CONTRACT,
    ...schema,
  };
}
