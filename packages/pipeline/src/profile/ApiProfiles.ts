import { ApiProfile } from "./ApiProfile.js";
import { BUILT_IN_API_PROFILES } from "./BuiltInApiProfiles.js";

/**
 * The API intent profiles this build ships (`profiles/<platform>/<api>/<version>`),
 * compiled once. The gateway reads one by the id its configuration names; a
 * native executor reads the one for the API it writes to, so both describe a
 * call the same way.
 */
export class ApiProfiles {
  private static compiled: ReadonlyMap<string, ApiProfile> | null = null;

  /** Every shipped profile id, in profile order. */
  public static ids(): readonly string[] {
    return [...ApiProfiles.all().keys()];
  }

  /** The shipped profile with this id, or null when the build has none. */
  public static get(id: string): ApiProfile | null {
    return ApiProfiles.all().get(id) ?? null;
  }

  private static all(): ReadonlyMap<string, ApiProfile> {
    if (ApiProfiles.compiled === null) {
      ApiProfiles.compiled = new Map(
        BUILT_IN_API_PROFILES.map((definition) => {
          const profile = ApiProfile.parse(definition);
          return [profile.id, profile] as const;
        }),
      );
    }
    return ApiProfiles.compiled;
  }
}
