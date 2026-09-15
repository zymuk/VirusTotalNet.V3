using System;
using System.Net;

namespace VirusTotalNet.V3.Core;

/// <summary>Base exception for all VirusTotal API errors.</summary>
public abstract class VirusTotalException : Exception
{
    /// <summary>Gets the error code from the API response (e.g., <c>QuotaExceededError</c>).</summary>
    public string? ErrorCode { get; }

    /// <summary>Creates a base API exception with a message and optional API error code.</summary>
    protected VirusTotalException(string message, string? errorCode = null)
        : base(message) => ErrorCode = errorCode;

    /// <summary>Creates a base API exception wrapping an inner exception.</summary>
    protected VirusTotalException(string message, Exception innerException, string? errorCode = null)
        : base(message, innerException) => ErrorCode = errorCode;
}

/// <summary>Exception thrown when the VirusTotal API returns an error response (4xx/5xx).</summary>
public class VtHttpException : VirusTotalException
{
    /// <summary>Gets the HTTP status code of the failed response.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>Creates an HTTP exception with the failing status code.</summary>
    public VtHttpException(HttpStatusCode statusCode, string message, string? errorCode = null)
        : base(message, errorCode) => StatusCode = statusCode;

    /// <summary>Creates an HTTP exception wrapping an inner exception.</summary>
    public VtHttpException(HttpStatusCode statusCode, string message, Exception innerException, string? errorCode = null)
        : base(message, innerException, errorCode) => StatusCode = statusCode;
}

/// <summary>Exception thrown when the API quota is exceeded (HTTP 429 or <c>QuotaExceededError</c>).</summary>
public class QuotaExceededException : VtHttpException
{
    /// <summary>Creates a quota-exceeded exception.</summary>
    public QuotaExceededException(string message, string? errorCode = "QuotaExceededError")
        : base((HttpStatusCode)429, message, errorCode) { }
}

/// <summary>Exception thrown when the API key is invalid or missing (HTTP 401).</summary>
public class AuthenticationException : VtHttpException
{
    /// <summary>Creates an authentication exception.</summary>
    public AuthenticationException(string message, string? errorCode = "AuthenticationRequiredError")
        : base(HttpStatusCode.Unauthorized, message, errorCode) { }
}

/// <summary>Exception thrown when the requested resource is not found (HTTP 404).</summary>
public class NotFoundException : VtHttpException
{
    /// <summary>Creates a not-found exception.</summary>
    public NotFoundException(string message, string? errorCode = "NotFoundError")
        : base(HttpStatusCode.NotFound, message, errorCode) { }
}

/// <summary>Exception thrown when the request is invalid or malformed (HTTP 400).</summary>
public class InvalidRequestException : VtHttpException
{
    /// <summary>Creates an invalid-request exception.</summary>
    public InvalidRequestException(string message, string? errorCode = "BadRequestError")
        : base(HttpStatusCode.BadRequest, message, errorCode) { }
}

/// <summary>Exception thrown when the API returns a server error (HTTP 5xx).</summary>
public class ServerException : VtHttpException
{
    /// <summary>Creates a server exception.</summary>
    public ServerException(string message, string? errorCode = "InternalError")
        : base(HttpStatusCode.InternalServerError, message, errorCode) { }
}

/// <summary>Exception thrown when a <c>VtResult</c> carrying failure is unwrapped via <c>ValueOrThrow</c>.</summary>
public class VtResultException : VirusTotalException
{
    /// <summary>Creates a result-unwrap exception.</summary>
    public VtResultException(string message, string? errorCode = null)
        : base(message, errorCode) { }
}

/// <summary>Exception thrown when the rate limit is exceeded (HTTP 429 with retry-after).</summary>
public class RateLimitException : VtHttpException
{
    /// <summary>Gets the suggested retry-after delay from the <c>Retry-After</c> response header, when present.</summary>
    public TimeSpan? RetryAfter { get; }

    /// <summary>Creates a rate-limit exception with the optional suggested wait time.</summary>
    public RateLimitException(string message, TimeSpan? retryAfter = null, string? errorCode = "RateLimitExceededError")
        : base((HttpStatusCode)429, message, errorCode) => RetryAfter = retryAfter;
}

/// <summary>
/// Exception thrown when a request fails at the transport layer (network error or timeout) after all
/// configured retries. It carries no HTTP status because the server was never reached.
/// </summary>
public class VtNetworkException : VirusTotalException
{
    /// <summary>Creates a network exception wrapping the underlying transport failure.</summary>
    public VtNetworkException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
