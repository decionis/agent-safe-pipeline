export const defaultMaxJsonResponseBytes = 100 * 1024;

export async function readBoundedJsonResponse(
  response,
  { maxBytes = defaultMaxJsonResponseBytes } = {},
) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new Error("GITHUB_API_RESPONSE_LIMIT_INVALID");
  }

  const contentLength = response.headers?.get?.("content-length");
  if (/^\d+$/.test(contentLength ?? "") && BigInt(contentLength) > BigInt(maxBytes)) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error("GITHUB_API_RESPONSE_TOO_LARGE");
  }
  if (response.body === null || response.body === undefined) return null;

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let byteCount = 0;
  let text = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      byteCount += value.byteLength;
      if (byteCount > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error("GITHUB_API_RESPONSE_TOO_LARGE");
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } catch (error) {
    if (error instanceof Error && error.message === "GITHUB_API_RESPONSE_TOO_LARGE") {
      throw error;
    }
    throw new Error("GITHUB_API_RESPONSE_INVALID");
  } finally {
    reader.releaseLock();
  }

  if (text.length === 0) return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("GITHUB_API_RESPONSE_INVALID");
  }
}
