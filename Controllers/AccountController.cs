using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using SSOLoginService.Web.Services;

namespace SSOLoginService.Web.Controllers;

public class AccountController : Controller
{
    private const string SessionMelliCode = "LoginMelliCode";
    private const string SessionPhones = "LoginPhones";
    private const string SessionPhoneNumber = "LoginPhoneNumber";
    private const string SessionPhoneLabel = "LoginPhoneLabel";
    private const string SessionLoginState = "LoginState";
    private const string SessionReturnUrl = "ReturnUrl";

    private readonly AuthApiClient _authApiClient;
    private readonly ILogger<AccountController> _logger;

    public AccountController(AuthApiClient authApiClient, ILogger<AccountController> logger)
    {
        _authApiClient = authApiClient;
        _logger = logger;
    }

    [ActionName("login")]
    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
            return RedirectToFrontend();

        ViewBag.ReturnUrl = returnUrl ?? FrontendUrl;
        return View();
    }

    [ActionName("login")]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LoginPost(string melliCode, string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
            return RedirectToFrontend();

        ViewBag.ReturnUrl = returnUrl ?? FrontendUrl;
        ViewBag.MelliCode = melliCode;

        var normalized = NormalizeDigits(melliCode);
        if (string.IsNullOrWhiteSpace(normalized) || normalized.Length != 10 || !normalized.All(char.IsDigit))
        {
            ViewBag.Error = "کد ملی باید ۱۰ رقم باشد";
            return View("Login");
        }

        if (!string.IsNullOrEmpty(returnUrl))
            HttpContext.Session.SetString(SessionReturnUrl, returnUrl);

        var (phones, error) = await _authApiClient.SecondLoginAsync(normalized);
        if (phones == null || phones.Count == 0)
        {
            ViewBag.Error = error ?? "ورود با کد ملی ناموفق بود";
            return View("Login");
        }

        HttpContext.Session.SetString(SessionMelliCode, normalized);
        SavePhones(phones);

        return RedirectToAction(nameof(SelectPhone));
    }

    [HttpGet]
    public IActionResult SelectPhone()
    {
        if (User.Identity?.IsAuthenticated == true)
            return RedirectToFrontend();

        var melliCode = HttpContext.Session.GetString(SessionMelliCode);
        var phones = LoadPhones();
        if (string.IsNullOrEmpty(melliCode) || phones.Count == 0)
            return RedirectToAction("login");

        return View(phones);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SelectPhone(string phoneNumber)
    {
        if (User.Identity?.IsAuthenticated == true)
            return RedirectToFrontend();

        var melliCode = HttpContext.Session.GetString(SessionMelliCode);
        var phones = LoadPhones();
        if (string.IsNullOrEmpty(melliCode) || phones.Count == 0)
            return RedirectToAction("login");

        var selected = phones.FirstOrDefault(p =>
            string.Equals(p.Value, phoneNumber, StringComparison.Ordinal)
            || string.Equals(p.Label, phoneNumber, StringComparison.Ordinal));

        if (selected == null || string.IsNullOrWhiteSpace(selected.Value))
        {
            ViewBag.Error = "لطفا یک شماره تلفن معتبر انتخاب کنید";
            ViewBag.SelectedPhone = phoneNumber;
            return View(phones);
        }

        var (ok, error) = await _authApiClient.SendOtpAsync(selected.Value, melliCode);
        if (!ok)
        {
            ViewBag.Error = error ?? "ارسال کد تایید ناموفق بود";
            ViewBag.SelectedPhone = selected.Value;
            return View(phones);
        }

        HttpContext.Session.SetString(SessionPhoneNumber, selected.Value);
        HttpContext.Session.SetString(SessionPhoneLabel, selected.Label);

        return RedirectToAction(nameof(Otp));
    }

    [HttpGet]
    public IActionResult Otp()
    {
        if (User.Identity?.IsAuthenticated == true)
            return RedirectToFrontend();

        var melliCode = HttpContext.Session.GetString(SessionMelliCode);
        var phoneNumber = HttpContext.Session.GetString(SessionPhoneNumber);
        if (string.IsNullOrEmpty(melliCode) || string.IsNullOrEmpty(phoneNumber))
            return RedirectToAction("login");

        ViewBag.PhoneNumber = phoneNumber;
        ViewBag.PhoneLabel = HttpContext.Session.GetString(SessionPhoneLabel) ?? phoneNumber;
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Otp(string otpCode)
    {
        if (User.Identity?.IsAuthenticated == true)
            return RedirectToFrontend();

        var melliCode = HttpContext.Session.GetString(SessionMelliCode);
        var phoneNumber = HttpContext.Session.GetString(SessionPhoneNumber);
        var phoneLabel = HttpContext.Session.GetString(SessionPhoneLabel) ?? phoneNumber;

        ViewBag.PhoneNumber = phoneNumber;
        ViewBag.PhoneLabel = phoneLabel;

        if (string.IsNullOrEmpty(melliCode) || string.IsNullOrEmpty(phoneNumber))
            return RedirectToAction("login");

        var normalizedOtp = NormalizeDigits(otpCode);
        if (string.IsNullOrWhiteSpace(normalizedOtp) || normalizedOtp.Length != 5 || !normalizedOtp.All(char.IsDigit))
        {
            ViewBag.Error = "کد تایید باید ۵ رقم باشد";
            return View();
        }

        var (token, error) = await _authApiClient.VerifyOtpAsync(phoneNumber, normalizedOtp, melliCode);
        if (token == null || string.IsNullOrWhiteSpace(token.AccessToken))
        {
            ViewBag.Error = error ?? "کد تایید نامعتبر است";
            return View();
        }

        await SignInWithTokensAsync(token);
        ClearLoginSession(keepReturnUrl: true);

        return RedirectToAction(nameof(Success));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResendOtp()
    {
        var melliCode = HttpContext.Session.GetString(SessionMelliCode);
        var phoneNumber = HttpContext.Session.GetString(SessionPhoneNumber);
        if (string.IsNullOrEmpty(melliCode) || string.IsNullOrEmpty(phoneNumber))
            return RedirectToAction("login");

        var (ok, error) = await _authApiClient.SendOtpAsync(phoneNumber, melliCode);
        if (!ok)
        {
            ViewBag.Error = error ?? "ارسال مجدد کد تایید ناموفق بود";
            ViewBag.PhoneNumber = phoneNumber;
            ViewBag.PhoneLabel = HttpContext.Session.GetString(SessionPhoneLabel) ?? phoneNumber;
            return View("Otp");
        }

        return RedirectToAction(nameof(Otp));
    }

    [HttpGet]
    public IActionResult Success()
    {
        if (User.Identity?.IsAuthenticated != true)
            return RedirectToAction("login");

        ViewBag.FrontendUrl = HttpContext.Session.GetString(SessionReturnUrl) ?? FrontendUrl;
        return View();
    }

    [ActionName("redirect")]
    public async Task<IActionResult> RedirectToProvider(string provider = "moi", string? returnUrl = null)
    {
        var effectiveReturnUrl = returnUrl ?? FrontendUrl;
        HttpContext.Session.SetString(SessionReturnUrl, effectiveReturnUrl);

        var initiateUrl = await _authApiClient.InitiateLoginAsync(effectiveReturnUrl);
        if (!string.IsNullOrWhiteSpace(initiateUrl))
        {
            _logger.LogInformation("Redirecting via login/initiate URL");
            return Redirect(initiateUrl);
        }

        var state = Guid.NewGuid().ToString("N");
        HttpContext.Session.SetString(SessionLoginState, state);

        var callbackUrl = $"{Request.Scheme}://{Request.Host}/account/callback?provider={provider}";
        var moiAuthorizeUrl = "https://ssokeshvar.moi.ir/oauth2/authorize";
        var redirectUri = Uri.EscapeDataString(callbackUrl);
        var loginUrl = $"{moiAuthorizeUrl}" +
                       $"?response_type=code" +
                       $"&scope=openid%20profile" +
                       $"&client_id=sabzevar.ir" +
                       $"&state={state}" +
                       $"&redirect_uri={redirectUri}";

        _logger.LogInformation("Falling back to MOI SSO redirect: {Url}", loginUrl);
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

        var savedState = HttpContext.Session.GetString(SessionLoginState);
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

        await SignInWithTokensAsync(tokenResult);

        var returnUrl = HttpContext.Session.GetString(SessionReturnUrl) ?? FrontendUrl;
        ClearLoginSession(keepReturnUrl: false);

        return Redirect(returnUrl);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await _authApiClient.LogoutAsync();
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        Response.Cookies.Delete("accessToken");
        Response.Cookies.Delete("refreshToken");
        return RedirectToAction("login");
    }

    private async Task SignInWithTokensAsync(TokenResponse token)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, "sso-user"),
            new("access_token", token.AccessToken),
            new("refresh_token", token.RefreshToken ?? string.Empty)
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

        var expiresIn = token.ExpiresIn > 0 ? token.ExpiresIn : 3600;

        Response.Cookies.Append("accessToken", token.AccessToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = DateTime.UtcNow.AddSeconds(expiresIn),
            Path = "/"
        });

        if (!string.IsNullOrWhiteSpace(token.RefreshToken))
        {
            Response.Cookies.Append("refreshToken", token.RefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTime.UtcNow.AddDays(30),
                Path = "/"
            });
        }

        _logger.LogInformation("User authenticated successfully");
    }

    private void SavePhones(List<PhoneOption> phones)
    {
        var json = JsonSerializer.Serialize(phones);
        HttpContext.Session.SetString(SessionPhones, json);
    }

    private List<PhoneOption> LoadPhones()
    {
        var json = HttpContext.Session.GetString(SessionPhones);
        if (string.IsNullOrWhiteSpace(json))
            return new List<PhoneOption>();

        try
        {
            return JsonSerializer.Deserialize<List<PhoneOption>>(json) ?? new List<PhoneOption>();
        }
        catch
        {
            return new List<PhoneOption>();
        }
    }

    private void ClearLoginSession(bool keepReturnUrl)
    {
        HttpContext.Session.Remove(SessionMelliCode);
        HttpContext.Session.Remove(SessionPhones);
        HttpContext.Session.Remove(SessionPhoneNumber);
        HttpContext.Session.Remove(SessionPhoneLabel);
        HttpContext.Session.Remove(SessionLoginState);
        if (!keepReturnUrl)
            HttpContext.Session.Remove(SessionReturnUrl);
    }

    private IActionResult RedirectToFrontend()
    {
        return Redirect(FrontendUrl);
    }

    private string FrontendUrl =>
        HttpContext.RequestServices
            .GetRequiredService<IConfiguration>()
            .GetValue<string>("Frontend:Url") ?? "/";

    private static string NormalizeDigits(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var persian = "۰۱۲۳۴۵۶۷۸۹";
        var arabic = "٠١٢٣٤٥٦٧٨٩";
        var chars = value.Trim().Select(ch =>
        {
            var p = persian.IndexOf(ch);
            if (p >= 0) return (char)('0' + p);
            var a = arabic.IndexOf(ch);
            if (a >= 0) return (char)('0' + a);
            return ch;
        });

        return new string(chars.Where(char.IsDigit).ToArray());
    }
}
