using System;
using System.Collections.Generic;

namespace Decionis.VerifyingProvider;

/// <summary>
/// Where a provider keeps the grants it accepted, until their attestation
/// expires. <see cref="Record"/> answers true when the grant was not there and
/// is now, and false when it was: the second presentation. Shared by every
/// instance that can effect; the profile's step 8.
/// </summary>
public interface IReplayStore
{
    bool Record(string grantId, DateTimeOffset expiresAt);
}

/// <summary>
/// A replay store for one process: enough for a single instance, and for the
/// vectors. Expired grants are forgotten on the next record, which is why the
/// store needs no life beyond the lease.
/// </summary>
public sealed class MemoryReplayStore : IReplayStore
{
    private readonly Dictionary<string, DateTimeOffset> seen = new(StringComparer.Ordinal);
    private readonly Func<DateTimeOffset> now;
    private readonly object gate = new();

    public MemoryReplayStore(Func<DateTimeOffset> now)
    {
        this.now = now;
    }

    public MemoryReplayStore() : this(() => DateTimeOffset.UtcNow)
    {
    }

    public bool Record(string grantId, DateTimeOffset expiresAt)
    {
        lock (gate)
        {
            var current = now();
            var expired = new List<string>();
            foreach (var (grant, expiry) in seen)
            {
                if (expiry <= current)
                {
                    expired.Add(grant);
                }
            }
            foreach (var grant in expired)
            {
                seen.Remove(grant);
            }
            if (seen.ContainsKey(grantId))
            {
                return false;
            }
            seen[grantId] = expiresAt;
            return true;
        }
    }
}
