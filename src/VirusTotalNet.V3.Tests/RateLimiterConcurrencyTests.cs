using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;
using VirusTotalNet.V3.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.V3.Tests;

public class RateLimiterConcurrencyTests
{
    private static VtClient CreateClient(StubHttpMessageHandler handler, int perMinute, int perDay)
    {
        var options = new VirusTotalOptions
        {
            ApiKey = "test-key",
            RequestsPerMinute = perMinute,
            RequestsPerDay = perDay
        };
        options.Validate();
        return new VtClient(options, new HttpClient(handler));
    }

    [Fact]
    public async Task ConcurrentRequests_DoNotExceedPerMinuteLimit()
    {
        var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{ \"data\": { \"id\": \"abc\", \"type\": \"file\", \"attributes\": {} } }")
            });
        using var client = CreateClient(handler, perMinute: 2, perDay: 100);
        using var cts = new CancellationTokenSource();

        var tasks = new List<Task<VtResponse<TestFileObject>>>();
        for (var i = 0; i < 5; i++)
        {
            tasks.Add(client.GetAsync<TestFileObject>("files/abc", cts.Token));
        }

// Only two of the five requests can start within the minute window.
        await Task.WhenAll(tasks[0], tasks[1]);

        await Task.Delay(50);
        Assert.Equal(2, handler.Requests.Count);

        cts.Cancel();
        try { await Task.WhenAll(tasks); } catch (OperationCanceledException) { }
    }

    [Fact]
    public async Task ConcurrentRequests_DoNotExceedPerDayLimit()
    {
        var handler = new StubHttpMessageHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{ \"data\": { \"id\": \"abc\", \"type\": \"file\", \"attributes\": {} } }")
            });
        using var client = CreateClient(handler, perMinute: 100, perDay: 1);
        using var cts = new CancellationTokenSource();

        var tasks = new List<Task<VtResponse<TestFileObject>>>();
        for (var i = 0; i < 3; i++)
        {
            tasks.Add(client.GetAsync<TestFileObject>("files/abc", cts.Token));
        }

        // Only one of the three requests can start within the day window.
        await Task.WhenAll(tasks[0]);

        await Task.Delay(50);
        Assert.Single(handler.Requests);

        cts.Cancel();
        try { await Task.WhenAll(tasks); } catch (OperationCanceledException) { }
    }
}