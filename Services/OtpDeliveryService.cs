using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;

namespace SSOLoginService.Web.Services;

public class OtpDeliveryService
{
    private const int DefaultResendCooldownSeconds = 120;

    private static readonly ConcurrentDictionary<string, SemaphoreSlim> SendLocks = new(StringComparer.Ordinal);

    private readonly AuthApiClient _authApiClient;
    private readonly SmsService _smsService;
    private readonly IConfiguration _configuration;
    private readonly IMemoryCache _cache;
    private readonly ILogger<OtpDeliveryService> _logger;

    public OtpDeliveryService(
        AuthApiClient authApiClient,
        SmsService smsService,
        IConfiguration configuration,
        IMemoryCache cache,
        ILogger<OtpDeliveryService> logger)
    {
        _authApiClient = authApiClient;
        _smsService = smsService;
        _configuration = configuration;
        _cache = cache;
        _logger = logger;
    }

    public async Task<(bool Ok, string? Error)> SendOtpWithSmsAsync(string phoneNumber, string melliCode)
    {
        var cacheKey = BuildResendCacheKey(phoneNumber, melliCode);
        var gate = SendLocks.GetOrAdd(cacheKey, _ => new SemaphoreSlim(1, 1));

        if (!await gate.WaitAsync(TimeSpan.Zero))
        {
            _logger.LogWarning(
                "Concurrent OTP send rejected for phone ending {Suffix}",
                SafeSuffix(phoneNumber));
            return (false, "درخواست قبلی هنوز در حال پردازش است. چند لحظه صبر کنید.");
        }

        try
        {
            if (_cache.TryGetValue(cacheKey, out _))
                return (false, "حداکثر یک بار در هر ۲ دقیقه می‌توانید کد دریافت کنید");

            var cooldownSeconds = _configuration.GetValue(
                "Otp:ResendCooldownSeconds",
                DefaultResendCooldownSeconds);

            _cache.Set(cacheKey, true, TimeSpan.FromSeconds(cooldownSeconds));

            var (ok, otpCode, error) = await _authApiClient.SendOtpAsync(phoneNumber, melliCode);
            if (!ok)
            {
                return (false, error);
            }

            if (string.IsNullOrWhiteSpace(otpCode))
            {
                _logger.LogError(
                    "OTP code missing after send-otp for phone ending {Suffix}",
                    SafeSuffix(phoneNumber));
                return (false, "کد تایید دریافت نشد");
            }

            var sendFromWeb = _configuration.GetValue("Sms:SendFromWeb", true);
            if (!sendFromWeb)
            {
                _logger.LogInformation("Sms:SendFromWeb is false; OTP registered without ERP SMS");
                return (true, null);
            }

            var (smsOk, smsError) = await _smsService.SendLoginOtpAsync(phoneNumber, otpCode);
            if (!smsOk)
            {
                _logger.LogWarning(
                    "ERP SMS failed for phone ending {Suffix}; cooldown kept",
                    SafeSuffix(phoneNumber));
                return (false, smsError);
            }

            return (true, null);
        }
        finally
        {
            gate.Release();
        }
    }

    private static string BuildResendCacheKey(string phoneNumber, string melliCode) =>
        $"otp-send:{NormalizeDigits(melliCode)}:{NormalizeDigits(phoneNumber)}";

    private static string NormalizeDigits(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var persian = "۰۱۲۳۴۵۶۷۸۹";
        var arabic = "٠١٢٣٤٥٦٧٨٩";
        var digits = value.Trim().Select(ch =>
        {
            var p = persian.IndexOf(ch);
            if (p >= 0) return (char)('0' + p);
            var a = arabic.IndexOf(ch);
            if (a >= 0) return (char)('0' + a);
            return ch;
        }).Where(char.IsDigit);

        return new string(digits.ToArray());
    }

    private static string SafeSuffix(string value) =>
        value.Length <= 4 ? "****" : value[^4..];
}
