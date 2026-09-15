using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet.V3.Core;
using VirusTotalNet.V3.Models;
using VirusTotalNet.V3.Tests.TestInternals;
using Xunit;

namespace VirusTotalNet.V3.Tests;

public class ErrorHandlingTests
{
    // ---- Group A: HTTP status / error mapping ---------------------------

    [Fact]
    public async Task Get_200EmptyBody_ReturnsDefaultEnvelope()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        };
        using var client = CreateClient(new StubHttpMessageHandler(response));

        var result = await client.GetAsync<TestFileObject>("files/abc");

        Assert.Null(result.Data);
        Assert.Null(result.Error);
    }

    [Fact]
    public async Task Get_304NotModified_ThrowsVtHttpException_WithoutCrashing()
    {
        using var client = CreateClient(new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.NotModified)));

        var ex = await Assert.ThrowsAsync<VtHttpException>(() => client.GetAsync<TestFileObject>("files/abc"));

        Assert.Equal(HttpStatusCode.NotModified, ex.StatusCode);
    }

    [Fact]
    public async Task Get_400_InvalidArgumentError_MapsToInvalidRequestException()
    {
        var handler = ErrorHandler(HttpStatusCode.BadRequest, "InvalidArgumentError", "Bad request");
        using var client = CreateClient(handler);

        var ex = await Assert.ThrowsAsync<InvalidRequestException>(() => client.GetAsync<TestFileObject>("files/abc"));

        Assert.Equal("InvalidArgumentError", ex.ErrorCode);
        Assert.Equal("Bad request", ex.Message);
    }

    [Fact]
    public async Task Get_401_AuthenticationRequiredError_MapsToAuthenticationException()
    {
        var handler = ErrorHandler(HttpStatusCode.Unauthorized, "AuthenticationRequiredError", "Invalid key");
        using var client = CreateClient(handler);

        var ex = await Assert.ThrowsAsync<VirusTotalNet.V3.Core.AuthenticationException>(
            () => client.GetAsync<TestFileObject>("files/abc"));

        Assert.Equal("AuthenticationRequiredError", ex.ErrorCode);
    }

    [Fact]
    public async Task Get_403_UnknownErrorCode_FallsBackToVtHttpException()
    {
        var handler = ErrorHandler(HttpStatusCode.Forbidden, "ForbiddenError", "No access");
        using var client = CreateClient(handler);

        var ex = await Assert.ThrowsAsync<VtHttpException>(() => client.GetAsync<TestFileObject>("files/abc"));

        Assert.Equal("ForbiddenError", ex.ErrorCode);
        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
    }

    [Fact]
    public async Task Get_418_UnknownErrorCode_FallsBackToVtHttpException_PreservingStatusAndMessage()
    {
        var handler = ErrorHandler((HttpStatusCode)418, "CoffeePotError", "I'm a teapot");
        using var client = CreateClient(handler);

        var ex = await Assert.ThrowsAsync<VtHttpException>(() => client.GetAsync<TestFileObject>("files/abc"));

        Assert.Equal((HttpStatusCode)418, ex.StatusCode);
        Assert.Equal("CoffeePotError", ex.ErrorCode);
        Assert.Equal("I'm a teapot", ex.Message);
    }

    [Fact]
    public async Task Get_404_WithoutErrorEnvelope_ThrowsVtHttpException()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.NotFound, "<html>Not Found</html>"));
        using var client = CreateClient(handler);

        var ex = await Assert.ThrowsAsync<VtHttpException>(() => client.GetAsync<TestFileObject>("files/abc"));

        Assert.Equal(HttpStatusCode.NotFound, ex.StatusCode);
    }

    [Fact]
    public async Task Get_502_InternalError_MapsToServerException()
    {
        var handler = ErrorHandler(HttpStatusCode.BadGateway, "InternalError", "Server broke");
        using var client = CreateClient(handler);

        var ex = await Assert.ThrowsAsync<ServerException>(() => client.GetAsync<TestFileObject>("files/abc"));

        Assert.Equal("InternalError", ex.ErrorCode);
    }

    [Fact]
    public async Task Get_503_RetriesThenThrows_ServerException()
    {
        var handler = ErrorHandler(HttpStatusCode.ServiceUnavailable, "ServiceUnavailableError", "Down");
        using var client = CreateClient(handler, o =>
        {
            o.MaxRetries = 2;
            o.InitialRetryDelay = TimeSpan.FromMilliseconds(1);
        });

        var ex = await Assert.ThrowsAsync<ServerException>(() => client.GetAsync<TestFileObject>("files/abc"));

        Assert.Equal(3, handler.Requests.Count);
        Assert.Equal("ServiceUnavailableError", ex.ErrorCode);
    }

    [Fact]
    public async Task Get_429_RetryAfterHttpDate_IsRespected()
    {
        var retryAfterDate = DateTimeOffset.UtcNow.AddSeconds(1).ToString("R");
        var callCount = 0;
        var handler = new StubHttpMessageHandler(_ =>
        {
            callCount++;
            if (callCount == 1)
            {
                var response = StubHttpMessageHandler.Json(
                    HttpStatusCode.TooManyRequests,
                    "{ \"error\": { \"code\": \"RateLimitExceededError\", \"message\": \"Slow down\" } }");
                response.Headers.TryAddWithoutValidation("Retry-After", retryAfterDate);
                return response;
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{ \"data\": { \"id\": \"abc\", \"type\": \"file\", \"attributes\": {} } }")
            };
        });
        using var client = CreateClient(handler, o =>
        {
            o.MaxRetries = 1;
            o.InitialRetryDelay = TimeSpan.FromHours(1);
        });

        var result = await client.GetAsync<TestFileObject>("files/abc");

        // The HTTP-date Retry-After (~1s ahead) must override the huge initial backoff.
        Assert.Equal(2, handler.Requests.Count);
        Assert.NotNull(result.Data);
    }

    [Fact]
    public async Task Get_EnvelopeWithBothDataAndError_ErrorWins()
    {
        var handler = new StubHttpMessageHandler(StubHttpMessageHandler.Json(
            HttpStatusCode.OK,
            "{ \"data\": { \"id\": \"abc\", \"type\": \"file\", \"attributes\": {} }, \"error\": { \"code\": \"NotFoundError\", \"message\": \"gone\" } }"));
        using var client = CreateClient(handler);

        var ex = await Assert.ThrowsAsync<NotFoundException>(() => client.GetAsync<TestFileObject>("files/abc"));

        Assert.Equal("NotFoundError", ex.ErrorCode);
    }

    // ---- Group B: JSON edge cases ----------------------------------------

    [Fact]
    public async Task TryGet_200_MalformedJson_ReturnsFailure()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, "not-json!!"));
        using var client = CreateClient(handler);

        var result = await client.TryGetAsync<TestFileObject>("files/abc");

        Assert.False(result.IsSuccess);
        Assert.Equal("MalformedResponseError", result.Error!.Code);
        Assert.Equal(HttpStatusCode.OK, result.Error.StatusCode);
    }

    [Fact]
    public async Task TryGet_204NoContent_ReturnsSuccess()
    {
        var handler = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.NoContent));
        using var client = CreateClient(handler);

        var result = await client.TryGetAsync<TestFileObject>("files/abc");

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task Get_200_MalformedJson_ThrowsJsonException()
    {
        var handler = new StubHttpMessageHandler(
            StubHttpMessageHandler.Json(HttpStatusCode.OK, "not-json!!"));
        using var client = CreateClient(handler);

        var ex = await Assert.ThrowsAsync<JsonException>(() => client.GetAsync<TestFileObject>("files/abc"));

        Assert.Contains("not-json", ex.Message);
    }

    [Fact]
    public async Task TryGet_ErrorEnvelopeAfterRetries_ReturnsFailure_WithOriginalCode()
    {
        var handler = ErrorHandler(HttpStatusCode.ServiceUnavailable, "ServiceUnavailableError", "Down");
        using var client = CreateClient(handler, o =>
        {
            o.MaxRetries = 1;
            o.InitialRetryDelay = TimeSpan.FromMilliseconds(1);
        });

        var result = await client.TryGetAsync<TestFileObject>("files/abc");

        Assert.False(result.IsSuccess);
        Assert.Equal("ServiceUnavailableError", result.Error!.Code);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, result.Error.StatusCode);
        Assert.Equal(2, handler.Requests.Count);
    }

    // ---- Group D: transport edge cases -----------------------------------

    [Fact]
    public async Task Get_RetryBackoffCancelled_MidBackoff_ThrowsOperationCanceled()
    {
        var handler = ErrorHandler(HttpStatusCode.InternalServerError, "InternalError", "Boom");
        using var cts = new CancellationTokenSource();
        using var client = CreateClient(handler, o =>
        {
            o.MaxRetries = 2;
            o.InitialRetryDelay = TimeSpan.FromSeconds(2);
        });

        cts.CancelAfter(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.GetAsync<TestFileObject>("files/abc", cts.Token));

        // Only the first attempt went out; the token stopped the backoff before the retry.
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Get_Timeout_AfterRetries_ThrowsVtNetworkException()
    {
        var slowHandler = new SlowHandler(TimeSpan.FromSeconds(5));
        using var slowClient = CreateClient(slowHandler, o =>
        {
            o.Timeout = TimeSpan.FromMilliseconds(150);
            o.MaxRetries = 0;
            o.InitialRetryDelay = TimeSpan.FromMilliseconds(1);
        });

        var ex = await Assert.ThrowsAsync<VtNetworkException>(
            () => slowClient.GetAsync<TestFileObject>("files/abc"));

        Assert.IsType<TaskCanceledException>(ex.InnerException);
        Assert.Equal(1, slowHandler.Requests);
    }

    [Fact]
    public async Task Get_NetworkErrorAfterRetries_ThrowsVtNetworkException()
    {
        var handler = new StubHttpMessageHandler(_ => throw new HttpRequestException("connection refused"));
        using var client = CreateClient(handler, o =>
        {
            o.MaxRetries = 1;
            o.InitialRetryDelay = TimeSpan.FromMilliseconds(1);
        });

        var ex = await Assert.ThrowsAsync<VtNetworkException>(() => client.GetAsync<TestFileObject>("files/abc"));

        Assert.IsType<HttpRequestException>(ex.InnerException);
        Assert.Contains("2 attempt(s)", ex.Message);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task TryGet_NetworkErrorAfterRetries_ReturnsFailure()
    {
        var handler = new StubHttpMessageHandler(_ => throw new HttpRequestException("boom"));
        using var client = CreateClient(handler, o =>
        {
            o.MaxRetries = 1;
            o.InitialRetryDelay = TimeSpan.FromMilliseconds(1);
        });

        var result = await client.TryGetAsync<TestFileObject>("files/abc");

        Assert.False(result.IsSuccess);
        Assert.Equal("NetworkError", result.Error!.Code);
        Assert.Contains("2 attempt(s)", result.Error.Message);
        Assert.Equal(2, handler.Requests.Count);
    }

    // ---- helpers ---------------------------------------------------------

    private static VtClient CreateClient(HttpMessageHandler handler, Action<VirusTotalOptions>? configure = null)
    {
        var options = new VirusTotalOptions
        {
            ApiKey = "test-key",
            RequestsPerMinute = 4,
            RequestsPerDay = 500
        };
        configure?.Invoke(options);
        options.Validate();
        return new VtClient(options, new HttpClient(handler));
    }

    private static StubHttpMessageHandler ErrorHandler(HttpStatusCode status, string code, string message)
        => new(_ => StubHttpMessageHandler.Json(status, $"{{ \"error\": {{ \"code\": \"{code}\", \"message\": \"{message}\" }} }}"));

    private sealed class SlowHandler : HttpMessageHandler
    {
        private readonly TimeSpan _delay;

        public SlowHandler(TimeSpan delay) => _delay = delay;

        public int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            return Task.Run(async () =>
            {
                await Task.Delay(_delay, cancellationToken).ConfigureAwait(false);
                return new HttpResponseMessage(HttpStatusCode.OK);
            }, cancellationToken);
        }
    }
}