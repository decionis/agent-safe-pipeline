using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Decionis.VerifyingProvider;

/// <summary>
/// ASP.NET Core middleware that runs the profile in front of the endpoints
/// behind it: it buffers the body up to a bound, verifies, and either refuses
/// with the profile's status and body or hands the request on with the body
/// intact. The hop this runs in is a verifying provider only when the system
/// of record admits nothing but that hop (the profile's section 1).
/// </summary>
public sealed class VerifyingProviderMiddleware
{
    internal static readonly string[] Covered =
    {
        "content-digest", "idempotency-key", "x-agent-safe-intent-hash",
        "x-agent-safe-grant-id", "x-agent-safe-decision-id", "x-agent-safe-claim-attestation",
        "signature", "signature-input",
    };

    private readonly RequestDelegate next;
    private readonly VerifyingProvider provider;
    private readonly long maxBodyBytes;

    public VerifyingProviderMiddleware(RequestDelegate next, VerifyingProvider provider, long maxBodyBytes = 1L << 20)
    {
        this.next = next;
        this.provider = provider;
        this.maxBodyBytes = maxBodyBytes;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;
        request.EnableBuffering();
        byte[] body;
        using (var buffer = new MemoryStream())
        {
            var limited = new byte[8192];
            int read;
            while ((read = await request.Body.ReadAsync(limited, 0, limited.Length, context.RequestAborted)) > 0)
            {
                buffer.Write(limited, 0, read);
                if (buffer.Length > maxBodyBytes)
                {
                    await Refuse(context, StatusCodes.Status413PayloadTooLarge, "BODY_BEYOND_BOUND");
                    return;
                }
            }
            body = buffer.ToArray();
        }
        request.Body.Position = 0;
        var headers = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, values) in request.Headers)
        {
            var lower = name.ToLowerInvariant();
            if (values.Count > 1 && Array.IndexOf(Covered, lower) >= 0)
            {
                await Refuse(context, StatusCodes.Status409Conflict, Verdict.SignatureInvalidOrIncomplete);
                return;
            }
            headers[lower] = (values.Count == 0 ? "" : values[0] ?? "").Trim();
        }
        var verdict = provider.Verify(new ProviderRequest(
            request.Method, request.Path.Value ?? "/", body.Length == 0 ? null : body, headers));
        if (!verdict.Accepted)
        {
            await Refuse(context, StatusCodes.Status409Conflict, verdict.ReasonCode!);
            return;
        }
        await next(context);
    }

    private static async Task Refuse(HttpContext context, int status, string code)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        await context.Response.Body.WriteAsync(Encoding.UTF8.GetBytes($"{{\"status\":\"REJECTED\",\"reason_code\":\"{code}\"}}"), context.RequestAborted);
    }
}

/// <summary>Registers the middleware: <c>app.UseVerifyingProvider(options)</c>.</summary>
public static class VerifyingProviderApplicationBuilderExtensions
{
    public static IApplicationBuilder UseVerifyingProvider(this IApplicationBuilder app, ProviderOptions options, long maxBodyBytes = 1L << 20)
    {
        var provider = new VerifyingProvider(options);
        return app.UseMiddleware<VerifyingProviderMiddleware>(provider, maxBodyBytes);
    }
}
