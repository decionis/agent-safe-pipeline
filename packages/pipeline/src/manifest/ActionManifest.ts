import { createHash } from "node:crypto";
import { z } from "zod";
import type { ActionRegistry } from "../execution/ActionRegistry.js";
import { CanonicalIntentHasher } from "../intent/CanonicalIntentHasher.js";
import { JsonObjectSchema, type JsonObject, type JsonValue } from "../intent/JsonValue.js";
import {
  ApiOperationSchema,
  ApiProfile,
  ApiProfileDefinitionSchema,
} from "../profile/ApiProfile.js";
import {
  McpProfileDefinitionSchema,
  McpToolSchema,
  type McpToolProfile,
} from "../profile/McpToolProfile.js";

/**
 * `agent-safe.actions/1`: the action space an executor can run, as one
 * document. Each entry is an action an intent can name, where it comes from
 * (a family registered in code, an API profile's writes, an MCP profile's
 * tools), the JSON Schema its parameters are admitted against, the target
 * scopes it acts on, and the effect it produces when its source says.
 *
 * The authority reads it as the inventory a policy release has to cover:
 * Decionis refuses a release that leaves a manifest action matched by no
 * rule but its default. The contract is Decionis's (`ActionManifest` in its
 * OpenAPI); this is the producer.
 */
export const ACTION_MANIFEST_CONTRACT = "agent-safe.actions/1";

/** The most actions one manifest lists, and the most target scopes one action names. */
export const MAX_MANIFEST_ACTIONS = 500;
export const MAX_ACTION_TARGETS = 64;

const actionName = z
  .string()
  .max(120)
  .regex(/^[a-z][a-z0-9._:-]*$/);

export const ActionManifestSourceSchema = z.discriminatedUnion("kind", [
  /** A family registered in code, by the name its registration goes by. */
  z.strictObject({
    kind: z.literal("registry"),
    family: z
      .string()
      .max(40)
      .regex(/^[a-z][a-z0-9]*$/),
  }),
  /** An API profile's writes: the operations, in profile order, that become this action. */
  z.strictObject({
    kind: z.literal("api"),
    profile: ApiProfileDefinitionSchema.shape.id,
    operations: z.array(ApiOperationSchema.shape.id).min(1).max(200),
  }),
  /** An MCP profile's tool that becomes this action. */
  z.strictObject({
    kind: z.literal("mcp"),
    profile: McpProfileDefinitionSchema.shape.id,
    tool: McpToolSchema.shape.tool,
  }),
]);

export const ActionManifestEntrySchema = z.strictObject({
  action: actionName,
  source: ActionManifestSourceSchema,
  /** The JSON Schema (draft 2020-12, without `$schema`) the intent's parameters are admitted against. */
  parameters: JsonObjectSchema,
  /** Scope templates with `{name}` placeholders; none when the proposal names the target. */
  targets: z.array(z.string().min(1).max(500)).max(MAX_ACTION_TARGETS),
  /** The effect the action produces, when its source declares one. */
  effect_type: z
    .string()
    .regex(/^[A-Z][A-Z0-9_]{0,119}$/)
    .nullable(),
});

export const ActionManifestSchema = z
  .strictObject({
    manifest: z.literal(ACTION_MANIFEST_CONTRACT),
    actions: z.array(ActionManifestEntrySchema).min(1).max(MAX_MANIFEST_ACTIONS),
  })
  .superRefine((value, context) => {
    // Strictly ascending is sorted and unique at once: one action, one entry.
    for (let index = 1; index < value.actions.length; index += 1) {
      if (value.actions[index - 1]!.action >= value.actions[index]!.action)
        context.addIssue({
          code: "custom",
          path: ["actions", index, "action"],
          message: "actions are listed once each, in code-point order",
        });
    }
  });

export type ActionManifestSource = z.infer<typeof ActionManifestSourceSchema>;
export type ActionManifestEntry = z.infer<typeof ActionManifestEntrySchema>;
export type ActionManifestDocument = z.infer<typeof ActionManifestSchema>;

/** What a registry cannot say about an action and its family can: where it acts, and its effect. */
export interface ActionAnnotation {
  readonly targets: readonly string[];
  readonly effectType: string | null;
}

export class ActionManifestError extends Error {
  public constructor(
    public readonly code: "ACTION_MANIFEST_DUPLICATE_ACTION" | "ACTION_MANIFEST_INVALID",
    public readonly detail: string,
  ) {
    super(code);
    this.name = "ActionManifestError";
  }
}

export class ActionManifest {
  /**
   * A parameters schema as JSON Schema: the input side, since that is what an
   * intent carries, and a check zod cannot express (a refinement, a custom
   * type) as an open schema rather than a refusal to describe the action.
   */
  public static parametersJsonSchema(schema: z.ZodType): JsonObject {
    const generated = z.toJSONSchema(schema, {
      target: "draft-2020-12",
      io: "input",
      unrepresentable: "any",
    }) as Record<string, unknown>;
    delete generated["$schema"];
    return generated as JsonObject;
  }

  /** A sealed registry's actions, each annotated by the family that registered it. */
  public static fromRegistry(
    registry: ActionRegistry,
    family: string,
    annotate: (action: string) => ActionAnnotation,
  ): ActionManifestEntry[] {
    return registry.describe().map(({ action, parametersSchema }) => {
      const annotation = annotate(action);
      return {
        action,
        source: { kind: "registry", family },
        parameters: ActionManifest.parametersJsonSchema(parametersSchema),
        targets: [...annotation.targets],
        effect_type: annotation.effectType,
      };
    });
  }

  /**
   * An API profile's write actions, one entry each, with every operation that
   * becomes it and that operation's method and path template as a target. A
   * read is never an intent, so it is not in the action space.
   */
  public static fromApiProfile(
    profile: ApiProfile,
    parametersSchema: z.ZodType,
  ): ActionManifestEntry[] {
    const parameters = ActionManifest.parametersJsonSchema(parametersSchema);
    return profile.actions().map((action) => {
      const operations = profile.definition.operations.filter(
        (operation) => !ApiProfile.isRead(operation) && operation.action === action,
      );
      return {
        action,
        source: {
          kind: "api",
          profile: profile.id,
          operations: operations.map((operation) => operation.id),
        },
        parameters,
        targets: [
          ...new Set(operations.map((operation) => `${operation.method} ${operation.path}`)),
        ],
        effect_type: null,
      };
    });
  }

  /** An MCP profile's tools, one entry each, admitted against the tool's declared arguments. */
  public static fromMcpProfile(profile: McpToolProfile): ActionManifestEntry[] {
    return profile.tools().map((name) => {
      const tool = profile.tool(name)!;
      return {
        action: tool.action,
        source: { kind: "mcp", profile: profile.id, tool: tool.tool },
        parameters: ActionManifest.parametersJsonSchema(profile.argumentsSchema(name)),
        targets: [tool.target],
        effect_type: null,
      };
    });
  }

  /**
   * The document: every entry once, in code-point order of its action, held
   * to the contract. An action two sources both produce is refused by name,
   * since a grant names an action and only one handler can run under it.
   */
  public static document(entries: readonly ActionManifestEntry[]): ActionManifestDocument {
    const seen = new Set<string>();
    for (const entry of entries) {
      if (seen.has(entry.action))
        throw new ActionManifestError("ACTION_MANIFEST_DUPLICATE_ACTION", entry.action);
      seen.add(entry.action);
    }
    const parsed = ActionManifestSchema.safeParse({
      manifest: ACTION_MANIFEST_CONTRACT,
      actions: [...entries].sort((a, b) => (a.action < b.action ? -1 : 1)),
    });
    if (!parsed.success)
      throw new ActionManifestError(
        "ACTION_MANIFEST_INVALID",
        parsed.error.issues
          .slice(0, 3)
          .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
          .join("; "),
      );
    return parsed.data;
  }

  /** `sha256:` over the RFC 8785 form: what a signed release manifest records as `actionManifestDigest`. */
  public static digest(document: ActionManifestDocument): `sha256:${string}` {
    const canonical = CanonicalIntentHasher.stringify(document as unknown as JsonValue);
    return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
  }
}
