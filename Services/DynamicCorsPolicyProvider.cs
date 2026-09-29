using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.Options;

namespace SSOLoginService.Web.Services;

/// <summary>
/// Adds the "CitizenApps" policy's origin check on top of the configured policies:
/// static Cors:Origins plus trusted domains defined in sso-panel.
/// </summary>
public class DynamicCorsPolicyProvider : ICorsPolicyProvider
{
    public const string CitizenAppsPolicy = "CitizenApps";

    private readonly DefaultCorsPolicyProvider _inner;
    private readonly CorsPolicy _citizenApps;

    public DynamicCorsPolicyProvider(
        IOptions<CorsOptions> options,
        IConfiguration configuration,
        ClientAccessService access)
    {
        _inner = new DefaultCorsPolicyProvider(options);

        var staticOrigins = new HashSet<string>(
            configuration.GetSection("Cors:Origins").Get<string[]>() ?? ["https://test-137.sabzevar.ir"],
            StringComparer.OrdinalIgnoreCase);

        _citizenApps = new CorsPolicyBuilder()
            .SetIsOriginAllowed(origin => staticOrigins.Contains(origin) || access.IsOriginAllowed(origin))
            .AllowAnyHeader()
            .AllowAnyMethod()
            .SetPreflightMaxAge(TimeSpan.FromMinutes(10))
            .Build();
    }

    public Task<CorsPolicy?> GetPolicyAsync(HttpContext context, string? policyName) =>
        string.Equals(policyName, CitizenAppsPolicy, StringComparison.Ordinal)
            ? Task.FromResult<CorsPolicy?>(_citizenApps)
            : _inner.GetPolicyAsync(context, policyName);
}
