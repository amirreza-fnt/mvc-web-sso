using System.Text;

namespace SSOLoginService.Web.Services;

public class SmsService
{
    private const string DefaultSendUrl =
        "http://erp.sabzevar.ir/SubSystems/SMS/webservices/sms_send.aspx";

    private const string FooterLine = "مدیریت فناوری اطلاعات شهرداری سبزوار";

    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<SmsService> _logger;

    public SmsService(HttpClient httpClient, IConfiguration configuration, ILogger<SmsService> logger)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<(bool Ok, string? Error)> SendLoginOtpAsync(string phoneNumber, string otpCode)
    {
        var token = _configuration["Sms:Token"];
        if (string.IsNullOrWhiteSpace(token))
        {
            _logger.LogError("Sms:Token is not configured");
            return (false, "تنظیمات پیامک ناقص است");
        }

        var sendUrl = _configuration["Sms:SendUrl"] ?? DefaultSendUrl;
        var num = NormalizePhone(phoneNumber);
        if (string.IsNullOrWhiteSpace(num))
            return (false, "شماره تلفن نامعتبر است");

        var body = new StringBuilder()
            .Append("کد ورود : ")
            .Append(otpCode)
            .Append('\n')
            .Append(_configuration["Sms:FooterLine"] ?? FooterLine)
            .ToString();

        var query = new StringBuilder(sendUrl.TrimEnd('?', '&'))
            .Append('?')
            .Append("Token=").Append(Uri.EscapeDataString(token))
            .Append("&Num=").Append(Uri.EscapeDataString(num))
            .Append("&Body=").Append(Uri.EscapeDataString(body));

        try
        {
            _logger.LogInformation("Sending login OTP SMS to phone ending {Suffix}", SafeSuffix(num));

            var response = await _httpClient.GetAsync(query.ToString());
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("SMS gateway failed: {Status} - {Body}", response.StatusCode, content);
                return (false, "ارسال پیامک ناموفق بود");
            }

            _logger.LogInformation("SMS gateway responded: {Body}", content);
            return (true, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception while sending SMS");
            return (false, "خطا در ارسال پیامک");
        }
    }

    private static string NormalizePhone(string phoneNumber)
    {
        if (string.IsNullOrWhiteSpace(phoneNumber))
            return string.Empty;

        var persian = "۰۱۲۳۴۵۶۷۸۹";
        var arabic = "٠١٢٣٤٥٦٧٨٩";
        var digits = phoneNumber.Trim().Select(ch =>
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
