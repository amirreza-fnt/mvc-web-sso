using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using SSOLoginService.Web.Services;

namespace SSOLoginService.Web.Controllers;

public class AccountController : Controller
{
    private readonly AuthApiClient _authApiClient;
    private readonly ILogger<AccountController> _logger;

    public AccountController(AuthApiClient authApiClient, ILogger<AccountController> logger)
    {
        _authApiClient = authApiClient;
        _logger = logger;
    }

    [ActionName("login")]
    public IActionResult Login(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
            return RedirectToFrontend();

        ViewBag.ReturnUrl = returnUrl ?? FrontendUrl;
        return View();
    }

    [ActionName("redirect")]
    public IActionResult RedirectToProvider(string provider = "moi", string? returnUrl = null)
    {
        var state = Guid.NewGuid().ToString("N");

        HttpContext.Session.SetString("LoginState", state);
        if (!string.IsNullOrEmpty(returnUrl))
            HttpContext.Session.SetString("ReturnUrl", returnUrl);

        var callbackUrl = $"{Request.Scheme}://{Request.Host}/account/callback?provider={provider}";

        var moiAuthorizeUrl = "https://ssokeshvar.moi.ir/oauth2/authorize";
        var redirectUri = Uri.EscapeDataString(callbackUrl);
        var loginUrl = $"{moiAuthorizeUrl}" +
                       $"?response_type=code" +
                       $"&scope=openid%20profile" +
                       $"&client_id=sabzevar.ir" +
                       $"&state={state}" +
                       $"&redirect_uri={redirectUri}";

        _logger.LogInformation("Redirecting to MOI SSO: {Url}", loginUrl);
        return Redirect(loginUrl);
    }

    [ActionName("callback")]
    public async Task<IActionResult> Callback(string? code, string? state, string? provider = "moi", string? error = null)
    {
        if (!string.IsNullOrEmpty(error))
        {
            _logger.LogError("MOI SSO returned error: {Error}", error);
            return RedirectToAction("login", new { error = "خطا در احراز هویت توسط وزارت کشور" });
        }

        if (string.IsNullOrWhiteSpace(code))
        {
            _logger.LogWarning("No code received in callback");
            return RedirectToAction("login", new { error = "کد احراز هویت دریافت نشد" });
        }

        var savedState = HttpContext.Session.GetString("LoginState");
        if (!string.IsNullOrEmpty(savedState) && state != savedState)
        {
            _logger.LogWarning("State mismatch: expected={Expected}, received={Received}", savedState, state);
            return RedirectToAction("login", new { error = "خطای امنیتی: درخواست نامعتبر" });
        }

        _logger.LogInformation("Exchanging code for provider={Provider}", provider);

        var tokenResult = await _authApiClient.ExchangeCodeAsync(provider ?? "moi", code, state ?? "");

        if (tokenResult == null || string.IsNullOrWhiteSpace(tokenResult.AccessToken))
        {
            _logger.LogError("Failed to exchange code for token");
            return RedirectToAction("login", new { error = "خطا در دریافت توکن از سرویس احراز هویت" });
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, "sso-user"),
            new("access_token", tokenResult.AccessToken),
            new("refresh_token", tokenResult.RefreshToken)
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTime.UtcNow.AddHours(1)
            });

        Response.Cookies.Append("accessToken", tokenResult.AccessToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddSeconds(tokenResult.ExpiresIn),
            Path = "/"
        });

        Response.Cookies.Append("refreshToken", tokenResult.RefreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddDays(30),
            Path = "/"
        });

        _logger.LogInformation("User authenticated successfully, redirecting to frontend");

        var returnUrl = HttpContext.Session.GetString("ReturnUrl") ?? FrontendUrl;
        HttpContext.Session.Remove("LoginState");
        HttpContext.Session.Remove("ReturnUrl");

        return Redirect(returnUrl);
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        Response.Cookies.Delete("accessToken");
        Response.Cookies.Delete("refreshToken");
        return RedirectToAction("login");
    }

    private IActionResult RedirectToFrontend()
    {
        return Redirect(FrontendUrl);
    }

    private string FrontendUrl =>
        HttpContext.RequestServices
            .GetRequiredService<IConfiguration>()
            .GetValue<string>("Frontend:Url") ?? "/";
}
