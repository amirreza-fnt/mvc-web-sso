using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SSOLoginService.Web.Services;

public class ExchangeCodeRequest
{
    [JsonPropertyName("provider")]
    public string Provider { get; set; } = "moi";

    [JsonPropertyName("code")]
    public string Code { get; set; } = string.Empty;

    [JsonPropertyName("state")]
    public string State { get; set; } = string.Empty;
}

public class TokenResponse
{
    [JsonPropertyName("accessToken")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refreshToken")]
    public string RefreshToken { get; set; } = string.Empty;

    [JsonPropertyName("expiresIn")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("tokenType")]
    public string TokenType { get; set; } = "Bearer";
}

/// <summary>Backward-compatible alias used by existing callback flow. </summary>
public class ExchangeCodeResponse : TokenResponse
{
}

public class ApiResult<T>
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("data")]
    public T? Data { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }
}

public class SecondLoginRequest
{
    [JsonPropertyName("melliCode")]
    public string MelliCode { get; set; } = string.Empty;
}

public class PhoneOption
{
    [JsonPropertyName("phoneNumber")]
    public string? PhoneNumber { get; set; }

    [JsonPropertyName("value")]
    public string? ValueRaw { get; set; }

    [JsonPropertyName("maskedPhoneNumber")]
    public string? MaskedPhoneNumber { get; set; }

    [JsonPropertyName("label")]
    public string? LabelRaw { get; set; }

    [JsonPropertyName("display")]
    public string? Display { get; set; }

    [JsonIgnore]
    public string Value =>
        FirstNonEmpty(PhoneNumber, ValueRaw, MaskedPhoneNumber, LabelRaw, Display) ?? string.Empty;

    [JsonIgnore]
    public string Label =>
        FirstNonEmpty(MaskedPhoneNumber, LabelRaw, Display, PhoneNumber, ValueRaw) ?? Value;

    private static string? FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
}

public class SecondLoginData
{
    [JsonPropertyName("phones")]
    public List<PhoneOption>? Phones { get; set; }

    [JsonPropertyName("phoneNumbers")]
    public List<PhoneOption>? PhoneNumbers { get; set; }

    [JsonPropertyName("mobileNumbers")]
    public List<PhoneOption>? MobileNumbers { get; set; }

    [JsonIgnore]
    public List<PhoneOption> AllPhones =>
        Phones ?? PhoneNumbers ?? MobileNumbers ?? new List<PhoneOption>();
}

public class SendOtpRequest
{
    [JsonPropertyName("phoneNumber")]
    public string PhoneNumber { get; set; } = string.Empty;

    [JsonPropertyName("melliCode")]
    public string MelliCode { get; set; } = string.Empty;

    [JsonPropertyName("otpCode")]
    public string OtpCode { get; set; } = string.Empty;

    [JsonPropertyName("smsBody")]
    public string? SmsBody { get; set; }
}

public class VerifyOtpRequest
{
    [JsonPropertyName("phoneNumber")]
    public string PhoneNumber { get; set; } = string.Empty;

    [JsonPropertyName("otpCode")]
    public string OtpCode { get; set; } = string.Empty;

    [JsonPropertyName("melliCode")]
    public string MelliCode { get; set; } = string.Empty;
}

public class InitiateLoginRequest
{
    [JsonPropertyName("returnUrl")]
    public string ReturnUrl { get; set; } = string.Empty;
}

public class InitiateLoginData
{
    [JsonPropertyName("loginUrl")]
    public string? LoginUrl { get; set; }

    [JsonPropertyName("redirectUrl")]
    public string? RedirectUrl { get; set; }

    [JsonPropertyName("authorizeUrl")]
    public string? AuthorizeUrl { get; set; }

    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonIgnore]
    public string? ResolvedUrl =>
        FirstNonEmpty(LoginUrl, RedirectUrl, AuthorizeUrl, Url);

    private static string? FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
}

public class AuthApiClient
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly HttpClient _httpClient;
    private readonly ILogger<AuthApiClient> _logger;

    public AuthApiClient(HttpClient httpClient, ILogger<AuthApiClient> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<ExchangeCodeResponse?> ExchangeCodeAsync(string provider, string code, string state)
    {
        try
        {
            var request = new ExchangeCodeRequest
            {
                Provider = provider,
                Code = code,
                State = state
            };

            _logger.LogInformation("Exchanging code with API for provider={Provider}", provider);

            var response = await _httpClient.PostAsJsonAsync("/api/auth/exchange-code", request);
            var result = await ReadApiResultAsync<ExchangeCodeResponse>(response);

            if (!response.IsSuccessStatusCode || result == null || !result.Success)
            {
                _logger.LogError("Code exchange failed: {Status} - {Message}", response.StatusCode, result?.Message);
                return null;
            }

            return result.Data;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception in code exchange");
            return null;
        }
    }

    public async Task<(List<PhoneOption>? Phones, string? Error)> SecondLoginAsync(string melliCode)
    {
        try
        {
            var request = new SecondLoginRequest { MelliCode = melliCode };
            _logger.LogInformation("Calling second-login for melliCode ending {Suffix}", SafeSuffix(melliCode));

            var response = await _httpClient.PostAsJsonAsync("/api/auth/second-login", request);
            var raw = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                var failed = TryDeserialize<ApiResult<JsonElement>>(raw);
                _logger.LogError("Second-login failed: {Status} - {Body}", response.StatusCode, raw);
                return (null, failed?.Message ?? "خطا در دریافت اطلاعات کاربر");
            }

            var phones = ParsePhoneList(raw);
            if (phones.Count == 0)
            {
                _logger.LogWarning("Second-login returned no phones. Body={Body}", raw);
                return (null, "شماره تلفنی برای این کد ملی یافت نشد");
            }

            return (phones, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception in second-login");
            return (null, "خطا در ارتباط با سرویس احراز هویت");
        }
    }

    public async Task<(bool Ok, string? OtpCode, string? Error)> SendOtpAsync(string phoneNumber, string melliCode)
    {
        try
        {
            var otpCode = Random.Shared.Next(0, 100_000).ToString("D5");
            var request = new SendOtpRequest
            {
                PhoneNumber = phoneNumber,
                MelliCode = melliCode,
                OtpCode = otpCode,
                SmsBody = BuildLoginSmsBody(otpCode)
            };

            _logger.LogInformation("Sending OTP for phone ending {Suffix}", SafeSuffix(phoneNumber));

            var response = await _httpClient.PostAsJsonAsync("/api/auth/second-login/send-otp", request);
            var raw = await response.Content.ReadAsStringAsync();
            var result = TryDeserialize<ApiResult<JsonElement>>(raw);

            if (!response.IsSuccessStatusCode || (result != null && result.Success == false))
            {
                _logger.LogError("Send OTP failed: {Status} - {Message}", response.StatusCode, result?.Message);
                return (false, null, result?.Message ?? "ارسال کد تایید ناموفق بود");
            }

            var resolvedOtp = TryExtractOtpCode(raw) ?? otpCode;
            return (true, resolvedOtp, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception in send-otp");
            return (false, null, "خطا در ارتباط با سرویس احراز هویت");
        }
    }

    public async Task<(TokenResponse? Token, string? Error)> VerifyOtpAsync(
        string phoneNumber,
        string otpCode,
        string melliCode)
    {
        try
        {
            var request = new VerifyOtpRequest
            {
                PhoneNumber = phoneNumber,
                OtpCode = otpCode,
                MelliCode = melliCode
            };

            _logger.LogInformation("Verifying OTP for phone ending {Suffix}", SafeSuffix(phoneNumber));

            var response = await _httpClient.PostAsJsonAsync("/api/auth/second-login/verify-otp", request);
            var raw = await response.Content.ReadAsStringAsync();
            var result = TryDeserialize<ApiResult<TokenResponse>>(raw);

            if (!response.IsSuccessStatusCode || result == null || !result.Success || result.Data == null
                || string.IsNullOrWhiteSpace(result.Data.AccessToken))
            {
                // Some APIs return tokens at root of data with different nesting
                var token = result?.Data ?? TryExtractToken(raw);
                if (token != null && !string.IsNullOrWhiteSpace(token.AccessToken))
                    return (token, null);

                _logger.LogError("Verify OTP failed: {Status} - {Body}", response.StatusCode, raw);
                return (null, result?.Message ?? "کد تایید نامعتبر است");
            }

            return (result.Data, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception in verify-otp");
            return (null, "خطا در ارتباط با سرویس احراز هویت");
        }
    }

    public async Task<string?> InitiateLoginAsync(string returnUrl)
    {
        try
        {
            var request = new InitiateLoginRequest { ReturnUrl = returnUrl };
            _logger.LogInformation("Initiating SSO login");

            var response = await _httpClient.PostAsJsonAsync("/api/auth/login/initiate", request);
            var raw = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Login initiate failed: {Status} - {Body}", response.StatusCode, raw);
                return null;
            }

            var wrapped = TryDeserialize<ApiResult<InitiateLoginData>>(raw);
            if (!string.IsNullOrWhiteSpace(wrapped?.Data?.ResolvedUrl))
                return wrapped!.Data!.ResolvedUrl;

            var direct = TryDeserialize<InitiateLoginData>(raw);
            if (!string.IsNullOrWhiteSpace(direct?.ResolvedUrl))
                return direct!.ResolvedUrl;

            // Plain string body
            if (raw.TrimStart().StartsWith('"'))
            {
                var asString = TryDeserialize<string>(raw);
                if (!string.IsNullOrWhiteSpace(asString))
                    return asString;
            }

            _logger.LogWarning("Login initiate succeeded but no URL found. Body={Body}", raw);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception in login/initiate");
            return null;
        }
    }

    public async Task LogoutAsync()
    {
        try
        {
            await _httpClient.PostAsync("/api/auth/logout", null);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Logout API call failed");
        }
    }

    private async Task<ApiResult<T>?> ReadApiResultAsync<T>(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync();
        return TryDeserialize<ApiResult<T>>(raw);
    }

    private static T? TryDeserialize<T>(string raw)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(raw, JsonOptions);
        }
        catch
        {
            return default;
        }
    }

    private static TokenResponse? TryExtractToken(string raw)
    {
        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;

            if (root.TryGetProperty("data", out var data))
                return JsonSerializer.Deserialize<TokenResponse>(data.GetRawText(), JsonOptions);

            return JsonSerializer.Deserialize<TokenResponse>(raw, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    private List<PhoneOption> ParsePhoneList(string raw)
    {
        var phones = new List<PhoneOption>();

        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;

            // ApiResult<SecondLoginData>
            if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("data", out var data))
            {
                phones.AddRange(ExtractPhonesFromElement(data));
                if (phones.Count > 0)
                    return phones;
            }

            phones.AddRange(ExtractPhonesFromElement(root));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to parse phone list from second-login response");
        }

        return phones;
    }

    private static List<PhoneOption> ExtractPhonesFromElement(JsonElement element)
    {
        var phones = new List<PhoneOption>();

        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
                phones.Add(ToPhoneOption(item));
            return phones.Where(p => !string.IsNullOrWhiteSpace(p.Value)).ToList();
        }

        if (element.ValueKind != JsonValueKind.Object)
            return phones;

        foreach (var name in new[] { "phones", "phoneNumbers", "mobileNumbers", "mobiles", "data" })
        {
            if (!element.TryGetProperty(name, out var arr) || arr.ValueKind != JsonValueKind.Array)
                continue;

            foreach (var item in arr.EnumerateArray())
                phones.Add(ToPhoneOption(item));

            if (phones.Count > 0)
                break;
        }

        // Single phone fields
        if (phones.Count == 0)
        {
            foreach (var name in new[] { "phoneNumber", "mobile", "maskedPhoneNumber" })
            {
                if (element.TryGetProperty(name, out var single) && single.ValueKind == JsonValueKind.String)
                {
                    var value = single.GetString();
                    if (!string.IsNullOrWhiteSpace(value))
                        phones.Add(new PhoneOption { PhoneNumber = value, MaskedPhoneNumber = value });
                }
            }
        }

        return phones.Where(p => !string.IsNullOrWhiteSpace(p.Value)).ToList();
    }

    private static PhoneOption ToPhoneOption(JsonElement item)
    {
        if (item.ValueKind == JsonValueKind.String)
        {
            var value = item.GetString() ?? string.Empty;
            return new PhoneOption { PhoneNumber = value, MaskedPhoneNumber = value };
        }

        return JsonSerializer.Deserialize<PhoneOption>(item.GetRawText(), JsonOptions) ?? new PhoneOption();
    }

    private static string SafeSuffix(string value) =>
        value.Length <= 4 ? "****" : value[^4..];

    public static string BuildLoginSmsBody(string otpCode, string? footerLine = null) =>
        $"کد ورود : {otpCode}\n{footerLine ?? "مدیریت فناوری اطلاعات شهرداری سبزوار"}";

    private static string? TryExtractOtpCode(string raw)
    {
        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;

            if (TryExtractOtpFromObject(root, out var fromRoot))
                return fromRoot;

            if (root.TryGetProperty("data", out var data) && TryExtractOtpFromObject(data, out var fromData))
                return fromData;
        }
        catch
        {
            // ignore parse errors
        }

        return null;
    }

    private static bool TryExtractOtpFromObject(JsonElement element, out string? otpCode)
    {
        otpCode = null;
        if (element.ValueKind != JsonValueKind.Object)
            return false;

        foreach (var name in new[] { "otpCode", "OtpCode", "code", "verificationCode", "otp" })
        {
            if (!element.TryGetProperty(name, out var prop))
                continue;

            var value = prop.ValueKind == JsonValueKind.Number
                ? prop.GetInt32().ToString("D5")
                : prop.GetString();

            if (!IsValidOtp(value))
                continue;

            otpCode = value;
            return true;
        }

        return false;
    }

    private static bool IsValidOtp(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length == 5
        && value.All(char.IsDigit);
}
