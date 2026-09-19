using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Decionis.VerifyingProvider;

/// <summary>
/// "sha256:" and the hex SHA-256 over the RFC 8785 canonical form of a JSON
/// object, or a refusal when the text is not one that is I-JSON: not valid
/// UTF-8, not an object, a name repeated within one object, or a lone
/// surrogate escape, each of which another parser would read differently.
/// The canonicaliser is this library's own: names by UTF-16 code unit, numbers
/// as ECMAScript prints them, strings escaped as RFC 8785 section 3.2.2.2 lists.
/// </summary>
public static class CanonicalDigest
{
    /// <summary>Thrown when the body has no canonical form a provider may digest.</summary>
    public sealed class NotIJsonException : Exception
    {
        public NotIJsonException(string message) : base(message)
        {
        }

        public NotIJsonException(string message, Exception inner) : base(message, inner)
        {
        }
    }

    public static string Of(byte[] body)
    {
        JsonDocument document;
        try
        {
            // Utf8JsonReader refuses invalid UTF-8 and a lone surrogate escape;
            // it keeps every occurrence of a repeated name, which the walk refuses.
            document = JsonDocument.Parse(body, new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow });
        }
        catch (JsonException e)
        {
            throw new NotIJsonException("not JSON", e);
        }
        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new NotIJsonException("not a JSON object");
            }
            var canonical = CanonicalJson(document.RootElement);
            var sum = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
            return "sha256:" + Convert.ToHexString(sum).ToLowerInvariant();
        }
    }

    /// <summary>The RFC 8785 canonical form of a parsed value.</summary>
    public static string CanonicalJson(JsonElement element)
    {
        var out_ = new StringBuilder();
        try
        {
            Write(element, out_);
        }
        catch (InvalidOperationException e)
        {
            // The reader accepts the text and refuses the string on reading it:
            // a lone surrogate escape, which another parser would replace.
            throw new NotIJsonException("not I-JSON", e);
        }
        return out_.ToString();
    }

    private static void Write(JsonElement element, StringBuilder out_)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Null:
                out_.Append("null");
                break;
            case JsonValueKind.True:
                out_.Append("true");
                break;
            case JsonValueKind.False:
                out_.Append("false");
                break;
            case JsonValueKind.Number:
                out_.Append(Es6Number.Format(element.GetDouble()));
                break;
            case JsonValueKind.String:
                WriteString(element.GetString() ?? "", out_);
                break;
            case JsonValueKind.Array:
                out_.Append('[');
                var first = true;
                foreach (var item in element.EnumerateArray())
                {
                    if (!first)
                    {
                        out_.Append(',');
                    }
                    first = false;
                    Write(item, out_);
                }
                out_.Append(']');
                break;
            case JsonValueKind.Object:
                var members = new List<JsonProperty>();
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var member in element.EnumerateObject())
                {
                    if (!names.Add(member.Name))
                    {
                        throw new NotIJsonException("a name repeated within one object");
                    }
                    members.Add(member);
                }
                // RFC 8785 orders names by their UTF-16 code units, which ordinal comparison is.
                members.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
                out_.Append('{');
                for (var index = 0; index < members.Count; index++)
                {
                    if (index > 0)
                    {
                        out_.Append(',');
                    }
                    WriteString(members[index].Name, out_);
                    out_.Append(':');
                    Write(members[index].Value, out_);
                }
                out_.Append('}');
                break;
            default:
                throw new NotIJsonException("not JSON");
        }
    }

    private static void WriteString(string text, StringBuilder out_)
    {
        out_.Append('"');
        foreach (var unit in text)
        {
            switch (unit)
            {
                case '"': out_.Append("\\\""); break;
                case '\\': out_.Append("\\\\"); break;
                case '\b': out_.Append("\\b"); break;
                case '\f': out_.Append("\\f"); break;
                case '\n': out_.Append("\\n"); break;
                case '\r': out_.Append("\\r"); break;
                case '\t': out_.Append("\\t"); break;
                default:
                    if (unit < ' ')
                    {
                        out_.Append("\\u").Append(((int)unit).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        out_.Append(unit);
                    }
                    break;
            }
        }
        out_.Append('"');
    }
}

/// <summary>
/// A double as ECMAScript's Number::toString prints it, which RFC 8785 requires:
/// the shortest digits that round-trip, then the fixed or exponent form the
/// specification's thresholds choose. .NET's "R" gives the shortest digits;
/// the form is this class's.
/// </summary>
public static class Es6Number
{
    public static string Format(double value)
    {
        if (double.IsNaN(value) || double.IsInfinity(value))
        {
            throw new CanonicalDigest.NotIJsonException("not a finite number");
        }
        if (value == 0)
        {
            return "0";
        }
        var negative = value < 0;
        var shortest = Math.Abs(value).ToString("R", CultureInfo.InvariantCulture);
        // Split .NET's rendering into its digits and the decimal exponent n
        // such that the value is 0.d1d2...dk × 10^n.
        var exponent = 0;
        var mantissa = shortest;
        var e = shortest.IndexOfAny(new[] { 'E', 'e' });
        if (e >= 0)
        {
            exponent = int.Parse(shortest[(e + 1)..], CultureInfo.InvariantCulture);
            mantissa = shortest[..e];
        }
        var point = mantissa.IndexOf('.', StringComparison.Ordinal);
        var integerPart = point < 0 ? mantissa : mantissa[..point];
        var fractionPart = point < 0 ? "" : mantissa[(point + 1)..];
        var digits = (integerPart + fractionPart).TrimStart('0');
        var leadingZeros = (integerPart + fractionPart).Length - digits.Length;
        var n = integerPart.Length - leadingZeros + exponent;
        digits = digits.TrimEnd('0');
        var k = digits.Length;
        var sign = negative ? "-" : "";
        if (k <= n && n <= 21)
        {
            return sign + digits + new string('0', n - k);
        }
        if (0 < n && n <= 21)
        {
            return sign + digits[..n] + "." + digits[n..];
        }
        if (-6 < n && n <= 0)
        {
            return sign + "0." + new string('0', -n) + digits;
        }
        var exponentSign = n - 1 >= 0 ? "+" : "-";
        var magnitude = Math.Abs(n - 1).ToString(CultureInfo.InvariantCulture);
        return k == 1
            ? sign + digits + "e" + exponentSign + magnitude
            : sign + digits[..1] + "." + digits[1..] + "e" + exponentSign + magnitude;
    }
}
