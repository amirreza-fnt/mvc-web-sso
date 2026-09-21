namespace SSOLoginService.Web.Services;

public class OtpDeliveryService
{
    private readonly AuthApiClient _authApiClient;
    private readonly SmsService _smsService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<OtpDeliveryService> _logger;

    public OtpDeliveryService(
        AuthApiClient authApiClient,
        SmsService smsService,
        IConfiguration configuration,
        ILogger<OtpDeliveryService> logger)
    {
        _authApiClient = authApiClient;
        _smsService = smsService;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<(bool Ok, string? Error)> SendOtpWithSmsAsync(string phoneNumber, string melliCode)
    {
        var (ok, otpCode, error) = await _authApiClient.SendOtpAsync(phoneNumber, melliCode);
        if (!ok)
            return (false, error);

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
            return (false, smsError);

        return (true, null);
    }

    private static string SafeSuffix(string value) =>
        value.Length <= 4 ? "****" : value[^4..];
}
