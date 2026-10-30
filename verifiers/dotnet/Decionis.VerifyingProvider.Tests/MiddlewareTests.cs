using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Decionis.VerifyingProvider;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Xunit;

namespace Decionis.VerifyingProvider.Tests;

public class MiddlewareTests
{
    private static DefaultHttpContext Context(VectorRequest request)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = request.Method;
        context.Request.Path = request.Path;
        context.Request.QueryString = new QueryString("?trace=1");
        foreach (var (name, value) in request.Headers)
        {
            context.Request.Headers[name] = value;
        }
        context.Request.Body = new MemoryStream(request.Body ?? Array.Empty<byte>());
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static async Task<(int Status, string Body)> Run(VerifyingProviderMiddleware middleware, DefaultHttpContext context)
    {
        await middleware.InvokeAsync(context);
        context.Response.Body.Position = 0;
        return (context.Response.StatusCode, await new StreamReader(context.Response.Body).ReadToEndAsync());
    }

    /// <summary>The system of record behind the hop: it effects when reached, and reads the body it was handed.</summary>
    private static Task Effect(HttpContext context)
    {
        return context.Response.Body.WriteAsync(Encoding.UTF8.GetBytes("effected"), 0, 8);
    }

    [Theory]
    [InlineData("dispatch-replayed-within-lease")]
    [InlineData("payload-changed-after-claim")]
    [InlineData("copied-headers-unsigned")]
    public async Task TheMiddlewareAnswersTheVectorsOutcomes(string name)
    {
        var vector = Vector.Load(Path.Combine(Vector.Directory(), name + ".json"));
        var middleware = new VerifyingProviderMiddleware(Effect, new VerifyingProvider(vector.Options()));
        for (var index = 0; index < vector.Requests.Count; index++)
        {
            var request = vector.Requests[index];
            var (status, body) = await Run(middleware, Context(request));
            if (request.Outcome == "ACCEPT")
            {
                Assert.True(status == 200, $"{name} request {index}: {status} {body}");
                Assert.Equal("effected", body);
            }
            else
            {
                Assert.Equal(409, status);
                using var refusal = JsonDocument.Parse(body);
                Assert.Equal("REJECTED", refusal.RootElement.GetProperty("status").GetString());
                Assert.Equal(request.ReasonCode, refusal.RootElement.GetProperty("reason_code").GetString());
            }
        }
    }

    [Fact]
    public async Task TheMiddlewareHandsTheVerifiedAttestationToTheEndpoint()
    {
        var vector = Vector.Load(Path.Combine(Vector.Directory(), "state-version-left-to-the-write.json"));
        ClaimAttestation? handed = null;
        var middleware = new VerifyingProviderMiddleware(
            context =>
            {
                Assert.True(VerifyingProviderMiddleware.TryGetAttestation(context, out handed));
                Assert.Same(handed, context.Items[VerifyingProviderMiddleware.AttestationItem]);
                return Effect(context);
            },
            new VerifyingProvider(vector.Options()));
        var (status, body) = await Run(middleware, Context(vector.Requests[0]));
        Assert.True(status == 200, $"{status} {body}");
        Assert.Equal("effected", body);
        Assert.Equal("\"17\"", handed!.ExpectedStateVersion);
        var refused = Context(vector.Requests[0]);
        (status, _) = await Run(middleware, refused);
        Assert.Equal(409, status);
        Assert.False(VerifyingProviderMiddleware.TryGetAttestation(refused, out _));
    }

    /// <summary>
    /// A read the executor signed over <c>/v1/accounts/acme%20corp</c>, with the vector's HMAC key.
    /// The host decodes <see cref="HttpRequest.Path"/> and may move a prefix to
    /// <see cref="HttpRequest.PathBase"/>; the signature is over the path as it arrived.
    /// </summary>
    private static DefaultHttpContext EncodedPathRead(Vector vector, string rawTarget, string pathBase, string path)
    {
        var key = JsonDocument.Parse(File.ReadAllText(Path.Combine(Vector.Directory(), vector.Name + ".json")))
            .RootElement.GetProperty("executor_keys").EnumerateArray()
            .First(candidate => candidate.GetProperty("alg").GetString() == "hmac-sha256");
        var keyId = key.GetProperty("keyid").GetString()!;
        var headers = new Dictionary<string, string>(vector.Requests[0].Headers, StringComparer.Ordinal);
        var parameters = "(\"@method\" \"@path\" \"content-digest\" \"idempotency-key\" \"x-agent-safe-intent-hash\")"
            + $";created={vector.Now.ToUnixTimeSeconds()};keyid=\"{keyId}\";alg=\"hmac-sha256\"";
        var signatureBase = string.Join("\n",
            "\"@method\": GET",
            "\"@path\": /v1/accounts/acme%20corp",
            $"\"content-digest\": {headers["content-digest"]}",
            $"\"idempotency-key\": {headers["idempotency-key"]}",
            $"\"x-agent-safe-intent-hash\": {headers["x-agent-safe-intent-hash"]}",
            $"\"@signature-params\": {parameters}");
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key.GetProperty("shared_material_utf8").GetString()!));
        headers["signature-input"] = "agentsafe=" + parameters;
        headers["signature"] = $"agentsafe=:{Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(signatureBase)))}:";

        var context = Context(new VectorRequest
        {
            Method = "GET",
            Path = path,
            Headers = headers,
            Body = null,
            Target = null,
            Outcome = "ACCEPT",
            ReasonCode = null,
            ExpectedStateVersion = null,
        });
        context.Request.PathBase = pathBase;
        context.Features.Get<IHttpRequestFeature>()!.RawTarget = rawTarget;
        return context;
    }

    [Fact]
    public async Task TheMiddlewareVerifiesThePathAsReceivedNotAsDecoded()
    {
        var vector = Vector.Load(Path.Combine(Vector.Directory(), "read-base-components-accepts-for-read.json"));
        var middleware = new VerifyingProviderMiddleware(Effect, new VerifyingProvider(vector.Options()));

        var (status, body) = await Run(middleware, EncodedPathRead(vector, "/v1/accounts/acme%20corp?trace=1", "", "/v1/accounts/acme corp"));
        Assert.True(status == 200, $"{status} {body}");
        (status, body) = await Run(middleware, EncodedPathRead(vector, "/v1/accounts/acme%20corp", "/v1", "/accounts/acme corp"));
        Assert.True(status == 200, $"under Map: {status} {body}");
        (status, body) = await Run(middleware, EncodedPathRead(vector, "https://bank.example/v1/accounts/acme%20corp?trace=1", "", "/v1/accounts/acme corp"));
        Assert.True(status == 200, $"absolute form: {status} {body}");
        // Without a raw target the base and path are re-encoded, which gives back the same text here.
        (status, body) = await Run(middleware, EncodedPathRead(vector, "", "/v1", "/accounts/acme corp"));
        Assert.True(status == 200, $"no raw target: {status} {body}");

        // The decoded path is a different path: signed as received, it does not verify as decoded.
        (status, body) = await Run(middleware, EncodedPathRead(vector, "/v1/accounts/acme corp", "", "/v1/accounts/acme corp"));
        Assert.Equal(409, status);
        Assert.Contains(Verdict.SignatureInvalidOrIncomplete, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheMiddlewareRefusesACoveredHeaderReceivedTwiceAndABodyBeyondTheBound()
    {
        var vector = Vector.Load(Path.Combine(Vector.Directory(), "dispatch-attested-accepts.json"));
        var request = vector.Requests[0];
        var middleware = new VerifyingProviderMiddleware(Effect, new VerifyingProvider(vector.Options()));
        var twice = Context(request);
        twice.Request.Headers.Append("x-agent-safe-grant-id", request.Headers["x-agent-safe-grant-id"]);
        var (status, body) = await Run(middleware, twice);
        Assert.Equal(409, status);
        Assert.Contains(Verdict.SignatureInvalidOrIncomplete, body, StringComparison.Ordinal);
        var bounded = new VerifyingProviderMiddleware(Effect, new VerifyingProvider(vector.Options()), maxBodyBytes: 8);
        (status, body) = await Run(bounded, Context(request));
        Assert.Equal(413, status);
        Assert.Contains("BODY_BEYOND_BOUND", body, StringComparison.Ordinal);
    }
}
