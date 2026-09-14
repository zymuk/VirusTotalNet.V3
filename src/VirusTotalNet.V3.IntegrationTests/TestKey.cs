using System.Net;
using VirusTotalNet.V3.Core;

namespace VirusTotalNet.V3.IntegrationTests;

internal static class TestKey
{
    public const string TraitCategory = "Integration";

    public static string? ApiKey { get; } = Environment.GetEnvironmentVariable("VT_API_KEY", EnvironmentVariableTarget.User)
                                            ?? Environment.GetEnvironmentVariable("VT_API_KEY");

    public static bool IsAvailable => !string.IsNullOrWhiteSpace(ApiKey) && ApiKey.Length >= 32;

    public static VirusTotalOptions CreateOptions()
    {
        return new VirusTotalOptions
        {
            ApiKey = ApiKey!,
            RequestsPerMinute = 2,
            RequestsPerDay = 400,
            ThrowOnError = true,
            Timeout = TimeSpan.FromSeconds(120),
            UseRetry = true,
            MaxRetries = 2,
            InitialRetryDelay = TimeSpan.FromSeconds(2)
        };
    }

    public static void SkipIfUnavailable()
    {
        if (!IsAvailable)
            Skip.If(true, "VT_API_KEY not set — skipping integration test");
    }

    /// <summary>
    /// Runs a premium/licensed integration flow, turning an HTTP 403 ("not authorized")
    /// into a test skip with a note. Endpoints such as feeds, private scanning, hunting,
    /// retrohunt, saved searches and intelligence search require a license the current key
    /// may not have. Real API bugs still fail the test.
    /// </summary>
    public static async Task RunUnlicensedAwareAsync(Func<Task> body)
    {
        try
        {
            await body().ConfigureAwait(false);
        }
        catch (VtHttpException ex) when (ex.StatusCode == HttpStatusCode.Forbidden)
        {
            Skip.If(true, "Endpoint not licensed for this key (HTTP 403): " + ex.Message);
        }
    }
}
