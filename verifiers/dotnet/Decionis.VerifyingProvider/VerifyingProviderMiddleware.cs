using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Decionis.VerifyingProvider;

/// <summary>
/// ASP.NET Core middleware that runs the profile in front of the endpoints
/// behind it: it buffers the body up to a bound, verifies, and either refuses
/// with the profile's status and body or hands the request on with the body
/// intact. The hop this runs in is a verifying provider only when the system
/// of record admits nothing but that hop (the profile's section 1). An
/// accepted request reaches the endpoint with the verified
/// <see cref="ClaimAttestation"/> in <see cref="HttpContext.Items"/> under
/// <see cref="AttestationItem"/>, null for a read verified at VP-1 alone. An
/// endpoint whose write must hold to the target's version applies its
/// <see cref="ClaimAttestation.ExpectedStateVersion"/> as that write's
/// precondition, and builds a VP-3 receipt from it.
/// </summary>
public sealed class VerifyingProviderMiddleware
{
    /// <summary>The <see cref="HttpContext.Items"/> key an accepted request carries its verified attestation under.</summary>
    public const string AttestationItem = "Decionis.VerifyingProvider.Attestation";

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
        // The middleware reads no target, so it passes none, and step 9 is left
        // to the write behind it, with the attestation it is handed.
        var verdict = provider.Verify(new ProviderRequest(
            request.Method, PathAsReceived(context), body.Length == 0 ? null : body, headers));
        if (!verdict.Accepted)
        {
            await Refuse(context, StatusCodes.Status409Conflict, verdict.ReasonCode!);
            return;
        }
        context.Items[AttestationItem] = verdict.Attestation;
        await next(context);
    }

    /// <summary>
    /// The attestation the middleware verified for this request: true with it
    /// for an accepted dispatch, and false for a request the middleware did not
    /// accept, or a read verified at VP-1 alone.
    /// </summary>
    public static bool TryGetAttestation(HttpContext context, [NotNullWhen(true)] out ClaimAttestation? attestation)
    {
        attestation = context.Items.TryGetValue(AttestationItem, out var item) ? item as ClaimAttestation : null;
        return attestation is not null;
    }

    /// <summary>
    /// The path the executor signed: the request target as it arrived, percent-encoding intact,
    /// without its query. <see cref="HttpRequest.Path"/> will not do: it is decoded, so a signed
    /// <c>/accounts/acme%20corp</c> reads <c>/accounts/acme corp</c>, and under <c>Map</c> it has
    /// lost the prefix to <see cref="HttpRequest.PathBase"/>. Either way the signature would not
    /// verify. A host that exposes no raw target falls back to the base and path, re-encoded.
    /// </summary>
    internal static string PathAsReceived(HttpContext context)
    {
        var target = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (!string.IsNullOrEmpty(target))
        {
            // An absolute-form target, as a proxy receives it: its path starts after the authority.
            var scheme = target.IndexOf("://", StringComparison.Ordinal);
            if (target[0] != '/' && scheme > 0)
            {
                var slash = target.IndexOf('/', scheme + 3);
                var query = target.IndexOf('?', scheme + 3);
                target = slash < 0 || (query >= 0 && query < slash) ? "/" : target.Substring(slash);
            }
            if (target[0] == '/')
            {
                var query = target.IndexOf('?');
                return query < 0 ? target : target.Substring(0, query);
            }
        }
        var path = context.Request.PathBase.Add(context.Request.Path).ToUriComponent();
        return path.Length == 0 ? "/" : path;
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
