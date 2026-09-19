using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Decionis.VerifyingProvider;

namespace Decionis.VerifyingProvider.Tests;

/// <summary>What every test loads from a vector file.</summary>
public sealed class Vector
{
    public required string Name { get; init; }
    public required string Profile { get; init; }
    public required string Version { get; init; }
    public required bool Effects { get; init; }
    public required long ClockWindowSeconds { get; init; }
    public required DateTimeOffset Now { get; init; }
    public required string AuthorityIssuer { get; init; }
    public required List<ExecutorKey> ExecutorKeys { get; init; }
    public required Jwks AuthorityJwks { get; init; }
    public required List<VectorRequest> Requests { get; init; }

    /// <summary>The vectors live at the repository root; walk up to them from this project.</summary>
    public static string Directory()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "conformance", "provider", "vectors");
            if (System.IO.Directory.Exists(candidate))
            {
                return candidate;
            }
            directory = directory.Parent;
        }
        throw new InvalidOperationException("conformance/provider/vectors not found above this project");
    }

    public static IEnumerable<string> Files() => System.IO.Directory.GetFiles(Directory(), "*.json").OrderBy(path => path, StringComparer.Ordinal);

    public static Vector Load(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var root = document.RootElement;
        var provider = root.GetProperty("provider");
        var keys = new List<ExecutorKey>();
        foreach (var key in root.GetProperty("executor_keys").EnumerateArray())
        {
            keys.Add(key.GetProperty("alg").GetString() switch
            {
                "ed25519" => ExecutorKey.Ed25519(key.GetProperty("keyid").GetString()!, key.GetProperty("public_pem").GetString()!),
                "hmac-sha256" => ExecutorKey.Hmac(key.GetProperty("keyid").GetString()!, key.GetProperty("shared_material_utf8").GetString()!),
                var other => throw new InvalidOperationException($"unknown algorithm {other}"),
            });
        }
        var requests = new List<VectorRequest>();
        foreach (var request in root.GetProperty("requests").EnumerateArray())
        {
            var headers = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var header in request.GetProperty("headers").EnumerateObject())
            {
                headers[header.Name] = header.Value.GetString()!;
            }
            var body = request.GetProperty("body");
            var expect = request.GetProperty("expect");
            requests.Add(new VectorRequest
            {
                Method = request.GetProperty("method").GetString()!,
                Path = request.GetProperty("path").GetString()!,
                Headers = headers,
                Body = body.ValueKind == JsonValueKind.Null ? null : Encoding.UTF8.GetBytes(body.GetString()!),
                Outcome = expect.GetProperty("outcome").GetString()!,
                ReasonCode = expect.TryGetProperty("reason_code", out var code) ? code.GetString() : null,
            });
        }
        return new Vector
        {
            Name = root.GetProperty("vector").GetString()!,
            Profile = root.GetProperty("profile").GetString()!,
            Version = root.GetProperty("version").GetString()!,
            Effects = provider.GetProperty("effects").GetBoolean(),
            ClockWindowSeconds = provider.GetProperty("clock_window_seconds").GetInt64(),
            Now = DateTimeOffset.Parse(provider.GetProperty("now").GetString()!, System.Globalization.CultureInfo.InvariantCulture),
            AuthorityIssuer = provider.GetProperty("authority_issuer").GetString()!,
            ExecutorKeys = keys,
            AuthorityJwks = Jwks.Parse(root.GetProperty("authority_jwks").GetRawText()),
            Requests = requests,
        };
    }

    public ProviderOptions Options()
    {
        var now = Now;
        return new ProviderOptions(Effects, ExecutorKeys, AuthorityJwks, AuthorityIssuer, TimeSpan.FromSeconds(ClockWindowSeconds), new MemoryReplayStore(() => now), () => now);
    }
}

public sealed class VectorRequest
{
    public required string Method { get; init; }
    public required string Path { get; init; }
    public required Dictionary<string, string> Headers { get; init; }
    public required byte[]? Body { get; init; }
    public required string Outcome { get; init; }
    public required string? ReasonCode { get; init; }
}
