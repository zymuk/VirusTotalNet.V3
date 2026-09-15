using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalNet.V3.Core;

/// <summary>
/// Sliding‑window rate limiter that enforces both requests per minute and per day.
/// Supports injectable clock for deterministic testing.
/// </summary>
public sealed class RateLimiter
{
    private readonly ConcurrentQueue<DateTimeOffset> _minuteTimestamps = new();
    private readonly ConcurrentQueue<DateTimeOffset> _dayTimestamps = new();
    private readonly int _maxPerMinute;
    private readonly int _maxPerDay;
    private readonly Func<DateTimeOffset> _clock;
    private readonly object _sync = new();

    /// <summary>
    /// Default clock used when no clock is injected. Tests should inject a per-instance clock instead.
    /// </summary>
    public static Func<DateTimeOffset> Clock { get; set; } = static () => DateTimeOffset.UtcNow;

    private DateTimeOffset Now => _clock();

    /// <summary>Creates a rate limiter with the default VirusTotal limits (4 req/min, 500 req/day).</summary>
    public RateLimiter() : this(4, 500) { }

    /// <summary>Creates a rate limiter with explicit per-minute and per-day limits.</summary>
    public RateLimiter(int maxPerMinute, int maxPerDay) : this(maxPerMinute, maxPerDay, null) { }

    /// <summary>Creates a rate limiter with explicit limits and an injectable clock.</summary>
    public RateLimiter(int maxPerMinute, int maxPerDay, Func<DateTimeOffset>? clock)
    {
        _maxPerMinute = maxPerMinute;
        _maxPerDay = maxPerDay;
        _clock = clock ?? Clock;
    }

    /// <summary>
    /// Waits until a request slot is available according to both minute and day windows.
    /// </summary>
    public async Task WaitUntilAllowedAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            TimeSpan wait;

            lock (_sync)
            {
                var now = Now;
                PurgeExpired(_minuteTimestamps, now, TimeSpan.FromMinutes(1));
                PurgeExpired(_dayTimestamps, now, TimeSpan.FromDays(1));

                var waitMinute = _minuteTimestamps.Count >= _maxPerMinute
                    ? OldestWait(_minuteTimestamps, now, TimeSpan.FromMinutes(1))
                    : TimeSpan.Zero;

                var waitDay = _dayTimestamps.Count >= _maxPerDay
                    ? OldestWait(_dayTimestamps, now, TimeSpan.FromDays(1))
                    : TimeSpan.Zero;

                wait = waitMinute > waitDay ? waitMinute : waitDay;

                if (wait <= TimeSpan.Zero)
                {
                    _minuteTimestamps.Enqueue(now);
                    _dayTimestamps.Enqueue(now);
                    return;
                }
            }

            await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
        }
    }

    private static void PurgeExpired(ConcurrentQueue<DateTimeOffset> queue, DateTimeOffset now, TimeSpan window)
    {
        while (queue.TryPeek(out var oldest) && (now - oldest) >= window)
            queue.TryDequeue(out _);
    }

    private static TimeSpan OldestWait(ConcurrentQueue<DateTimeOffset> queue, DateTimeOffset now, TimeSpan window)
    {
        if (queue.TryPeek(out var oldest))
        {
            var elapsed = now - oldest;
            if (elapsed < window)
                return window - elapsed;
        }
        return TimeSpan.Zero;
    }
}
