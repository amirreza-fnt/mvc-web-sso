using SSOLoginService.Web.Services;

namespace SSOLoginService.Web.Middleware;

/// <summary>
/// Guards /api/*: a request is accepted when its Origin is a trusted domain (sso-panel or Cors:Origins)
/// or when it carries a valid X-Api-Key. Every call is logged to the sso-panel database.
/// </summary>
public class ApiAccessMiddleware
{
    public const string ApiKeyHeader = "X-Api-Key";

    private readonly RequestDelegate _next;
    private readonly ClientAccessService _access;
    private readonly ILogger<ApiAccessMiddleware> _logger;
    private readonly HashSet<string> _staticOrigins;

    public ApiAccessMiddleware(
        RequestDelegate next,
        ClientAccessService access,
        IConfiguration configuration,
        ILogger<ApiAccessMiddleware> logger)
    {
        _next = next;
        _access = access;
        _logger = logger;
        _staticOrigins = new HashSet<string>(
            configuration.GetSection("Cors:Origins").Get<string[]>() ?? Array.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_access.IsEnabled
            || !context.Request.Path.StartsWithSegments("/api")
            || HttpMethods.IsOptions(context.Request.Method))
        {
            await _next(context);
            return;
        }

        var origin = context.Request.Headers.Origin.ToString();
        var apiKey = context.Request.Headers[ApiKeyHeader].ToString();

        var identity = !string.IsNullOrEmpty(apiKey) ? _access.ValidateApiKey(apiKey) : null;
        identity ??= _access.MatchOrigin(origin);
        var allowed = identity != null
            || (!string.IsNullOrEmpty(origin) && _staticOrigins.Contains(origin.TrimEnd('/')));

        if (!allowed && _access.Enforce)
        {
            var dataUnavailable = !_access.HasLoaded;
            context.Response.StatusCode = dataUnavailable
                ? StatusCodes.Status503ServiceUnavailable
                : StatusCodes.Status401Unauthorized;

            _logger.LogWarning(
                "Rejected {Path} from {Ip} (origin={Origin}, keyPresent={KeyPresent})",
                context.Request.Path, context.Connection.RemoteIpAddress, origin, !string.IsNullOrEmpty(apiKey));

            await context.Response.WriteAsJsonAsync(new ApiResult<object>
            {
                Success = false,
                Message = dataUnavailable
                    ? "سرویس احراز سرویس‌گیرنده موقتا در دسترس نیست"
                    : "کلید API نامعتبر است یا دامنه شما مجاز نیست"
            });
            Log(context, identity, origin);
            return;
        }

        try
        {
            await _next(context);
        }
        finally
        {
            Log(context, identity, origin);
        }
    }

    private void Log(HttpContext context, ApiClientIdentity? identity, string origin) =>
        _access.EnqueueLog(new ApiRequestLogEntry(
            identity?.ClientId,
            identity?.ApiKeyId,
            string.IsNullOrEmpty(origin) ? null : origin,
            context.Request.Path.Value ?? string.Empty,
            context.Response.StatusCode,
            context.Connection.RemoteIpAddress?.ToString(),
            DateTime.UtcNow));
}
