using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Decionis.VerifyingProvider;
using Microsoft.AspNetCore.Http;
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
