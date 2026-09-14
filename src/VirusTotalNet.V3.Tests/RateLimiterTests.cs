using System;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.Tests;

public class RateLimiterTests
{
    [Fact]
    public async Task AllowsUpToPerMinuteLimit()
    {
        var now = DateTimeOffset.UnixEpoch;
        var limiter = new RateLimiter(2, 100, () => now);

        await limiter.WaitUntilAllowedAsync(default);
        await limiter.WaitUntilAllowedAsync(default);

        // Third call must wait because 2/min already used.
        var delayed = false;
        now = now.AddSeconds(1);
        var task = limiter.WaitUntilAllowedAsync(default);
        if (await Task.WhenAny(task, Task.Delay(50)) != task)
            delayed = true;

        Assert.True(delayed);
    }

    [Fact]
    public async Task ResetsAfterWindowElapses()
    {
        var now = DateTimeOffset.UnixEpoch;
        var limiter = new RateLimiter(1, 100, () => now);

        await limiter.WaitUntilAllowedAsync(default);

        // Advance past the 1-minute window.
        now = now.AddMinutes(1).AddSeconds(1);
        await limiter.WaitUntilAllowedAsync(default);

        Assert.True(true);
    }

    [Fact]
    public async Task EnforcesPerDayLimit()
    {
        var now = DateTimeOffset.UnixEpoch;
        var limiter = new RateLimiter(1000, 1, () => now);

        await limiter.WaitUntilAllowedAsync(default);

        // Second call within the same day must be throttled.
        var delayed = false;
        var task = limiter.WaitUntilAllowedAsync(default);
        if (await Task.WhenAny(task, Task.Delay(50)) != task)
            delayed = true;

        Assert.True(delayed);
    }
}