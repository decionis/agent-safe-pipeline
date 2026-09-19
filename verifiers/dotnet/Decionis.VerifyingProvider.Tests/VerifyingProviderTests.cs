using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Decionis.VerifyingProvider;
using Xunit;

namespace Decionis.VerifyingProvider.Tests;

public class VerifyingProviderTests
{
    public static IEnumerable<object[]> VectorFiles()
    {
        foreach (var file in Vector.Files())
        {
            yield return new object[] { file };
        }
    }

    [Fact]
    public void FindsTheVectors()
    {
        Assert.True(System.Linq.Enumerable.Count(Vector.Files()) >= 20);
    }

    [Theory]
    [MemberData(nameof(VectorFiles))]
    public void EveryVectorReachesTheOutcomesItNames(string file)
    {
        var vector = Vector.Load(file);
        Assert.Equal("agent-safe.verifying-provider/1", vector.Profile);
        Assert.Equal("0.1", vector.Version);
        var provider = new VerifyingProvider(vector.Options());
        for (var index = 0; index < vector.Requests.Count; index++)
        {
            var request = vector.Requests[index];
            var verdict = provider.Verify(new ProviderRequest(request.Method, request.Path, request.Body, request.Headers));
            var where = $"{vector.Name} request {index}";
            if (request.Outcome == "ACCEPT")
            {
                Assert.True(verdict.Accepted, $"{where}: {verdict.ReasonCode}");
                Assert.Null(verdict.ReasonCode);
                if (vector.Effects)
                {
                    Assert.NotNull(verdict.Attestation);
                }
            }
            else
            {
                Assert.False(verdict.Accepted, where);
                Assert.Equal(request.ReasonCode, verdict.ReasonCode);
                Assert.Null(verdict.Attestation);
            }
        }
    }

    [Theory]
    [InlineData("{\"a\":1,\"a\":2}")]
    [InlineData("{\"x\":{\"a\":1,\"b\":2,\"a\":3}}")]
    [InlineData("{\"x\":[1,{\"a\":1,\"a\":2}]}")]
    [InlineData("{\"\\u0061\":1,\"a\":2}")]
    [InlineData("{\"a\":\"\\udc00\"}")]
    [InlineData("{\"a\":\"\\ud83d\"}")]
    [InlineData("{\"a\":\"\\ud83d\\ud83d\"}")]
    [InlineData("{\"a\":\"\\ud83dx\"}")]
    [InlineData("{\"a\":1} {\"b\":2}")]
    [InlineData("not json")]
    [InlineData("")]
    [InlineData("5")]
    [InlineData("\"a\"")]
    [InlineData("[1]")]
    public void CanonicalDigestRefusesWhatOtherParsersReadDifferently(string body)
    {
        Assert.Throws<CanonicalDigest.NotIJsonException>(() => CanonicalDigest.Of(Encoding.UTF8.GetBytes(body)));
    }

    [Fact]
    public void CanonicalDigestRefusesBytesThatAreNotUtf8()
    {
        Assert.Throws<CanonicalDigest.NotIJsonException>(() => CanonicalDigest.Of(new byte[] { 0xff }));
    }

    [Theory]
    [InlineData("{\"a\":1,\"b\":{\"a\":2},\"c\":[{\"a\":3},{\"a\":4}],\"d\":[],\"e\":{}}")]
    [InlineData("{\"a\":\"\\ud83d\\ude80\",\"b\":\"\\\\ud83d\",\"c\":\"\\\\\\\\uDC00\"}")]
    [InlineData("{\"a\":\"\\\"\",\"a2\":\"\\\\\"}")]
    [InlineData(" {\"a\":1}")]
    public void CanonicalDigestAcceptsIJsonObjects(string body)
    {
        Assert.StartsWith("sha256:", CanonicalDigest.Of(Encoding.UTF8.GetBytes(body)), StringComparison.Ordinal);
    }

    [Fact]
    public void CanonicalDigestIsOverTheCanonicalForm()
    {
        var spaced = CanonicalDigest.Of(Encoding.UTF8.GetBytes("{\n  \"b\": 1,\n  \"a\": [1.50, 1e21, -0]\n}"));
        var compact = CanonicalDigest.Of(Encoding.UTF8.GetBytes("{\"a\":[1.5,1e+21,0],\"b\":1}"));
        Assert.Equal(compact, spaced);
    }

    [Fact]
    public void CanonicalFormFollowsRfc8785()
    {
        string Canonical(string text)
        {
            using var document = JsonDocument.Parse(text);
            return CanonicalDigest.CanonicalJson(document.RootElement);
        }
        Assert.Equal(
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u20ac$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}",
            Canonical("{\"numbers\":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],\"string\":\"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\"literals\":[null,true,false]}"));
        Assert.Equal(
            "{\"\\n\":\"Newline\",\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\u007f\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\ud83d\ude02\":\"Smiley\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
            Canonical("{\"\\u20ac\":\"Euro Sign\",\"\\r\":\"Carriage Return\",\"\\u000a\":\"Newline\",\"1\":\"One\",\"\\u0080\":\"Control\\u007f\",\"\\ud83d\\ude02\":\"Smiley\",\"\\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"));
        Assert.Equal("{\"Z\":0,\"za\":0,\"z\u00e9\":0,\"\u00c9clair\":0}", Canonical("{\"Z\":0,\"za\":0,\"z\\u00e9\":0,\"\\u00c9clair\":0}"));
        Assert.Equal("[0,1e+21,1e-7,0.1,100,1e+100,123456789012345680000,-1.5,100000000000000000000,0.000001]", Canonical("[-0,1e21,1e-7,0.1,100,1e100,123456789012345680000,-1.5,1e20,1e-6]"));
    }

    [Theory]
    [InlineData(0d, "0")]
    [InlineData(1d, "1")]
    [InlineData(1.5, "1.5")]
    [InlineData(-1.5, "-1.5")]
    [InlineData(1e21, "1e+21")]
    [InlineData(1e20, "100000000000000000000")]
    [InlineData(1e-6, "0.000001")]
    [InlineData(1e-7, "1e-7")]
    [InlineData(123456789012345680000d, "123456789012345680000")]
    [InlineData(5e-324, "5e-324")]
    [InlineData(1.7976931348623157e308, "1.7976931348623157e+308")]
    [InlineData(0.1, "0.1")]
    [InlineData(333333333.33333329, "333333333.3333333")]
    public void NumbersPrintAsEcmaScriptPrintsThem(double value, string expected)
    {
        Assert.Equal(expected, Es6Number.Format(value));
    }

    [Fact]
    public void MemoryReplayStoreForgetsAGrantOnceItsAttestationExpired()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_789_819_200);
        var store = new MemoryReplayStore(() => now);
        Assert.True(store.Record("g", now.AddSeconds(1)));
        Assert.False(store.Record("g", now.AddSeconds(1)));
        now = now.AddMilliseconds(999);
        Assert.False(store.Record("g", now.AddSeconds(5)));
        now = now.AddMilliseconds(1);
        Assert.True(store.Record("g", now.AddSeconds(5)));
    }
}
