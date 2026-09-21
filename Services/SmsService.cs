using System.Net;
using System.Text;

namespace SSOLoginService.Web.Services;

public class SmsService
{
    private const string SmsPath = "/SubSystems/SMS/webservices/sms_send.aspx";

    private const string DefaultInternalSendUrl = "http://192.168.1.30" + SmsPath;

    private const string DefaultPublicSendUrl = "http://erp.sabzevar.ir" + SmsPath;

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

        var num = NormalizePhone(phoneNumber);
        if (string.IsNullOrWhiteSpace(num) || num.Length < 10)
        {
            _logger.LogError("Invalid phone for SMS: {Phone}", phoneNumber);
            return (false, "شماره تلفن نامعتبر است");
        }

        var footer = _configuration["Sms:FooterLine"] ?? FooterLine;
        var body = AuthApiClient.BuildLoginSmsBody(otpCode, footer);
        var hostHeader = _configuration["Sms:HostHeader"];

        _logger.LogInformation("Sending login OTP SMS to phone ending {Suffix}", SafeSuffix(num));

        string? lastError = null;
        foreach (var sendUrl in GetSendUrls())
        {
            var url = BuildSendUrl(sendUrl, token, num, body);
            _logger.LogInformation("Trying SMS gateway {Gateway}", sendUrl);

            var (ok, error) = await SendGatewayRequestAsync(url, hostHeader);
            if (ok)
                return (true, null);

            lastError = error;
            _logger.LogWarning("SMS gateway failed for {Gateway}: {Error}", sendUrl, error);
        }

        return (false, lastError ?? "ارسال پیامک ناموفق بود");
    }

    private IEnumerable<string> GetSendUrls()
    {
        var configured = _configuration.GetSection("Sms:SendUrls").Get<string[]>();
        if (configured is { Length: > 0 })
        {
            foreach (var url in configured.Where(u => !string.IsNullOrWhiteSpace(u)))
                yield return url.Trim();
            yield break;
        }

        var primary = _configuration["Sms:SendUrl"];
        if (string.IsNullOrWhiteSpace(primary))
            primary = DefaultInternalSendUrl;

        yield return primary.Trim();

        var fallback = _configuration["Sms:FallbackSendUrl"];
        if (string.IsNullOrWhiteSpace(fallback))
            fallback = DefaultPublicSendUrl;

        fallback = fallback.Trim();
        if (!string.Equals(primary, fallback, StringComparison.OrdinalIgnoreCase))
            yield return fallback;
    }

    private async Task<(bool Ok, string? Error)> SendGatewayRequestAsync(Uri url, string? hostHeader)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (!string.IsNullOrWhiteSpace(hostHeader))
                request.Headers.Host = hostHeader;

            using var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead);

            var content = string.Empty;
            try
            {
                content = await response.Content.ReadAsStringAsync();
            }
            catch (Exception readEx) when (IsAbruptGatewayClose(readEx))
            {
                _logger.LogWarning(
                    readEx,
                    "SMS gateway closed while reading body (status {Status}); assuming SMS was sent",
                    response.StatusCode);

                return (true, null);
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("SMS gateway failed: {Status} - {Body}", response.StatusCode, content);
                return (false, "ارسال پیامک ناموفق بود");
            }

            _logger.LogInformation("SMS gateway responded: {Body}", content);
            return (true, null);
        }
        catch (Exception ex) when (IsAbruptGatewayClose(ex))
        {
            _logger.LogWarning(ex, "SMS gateway closed connection abruptly; assuming SMS was sent");
            return (true, null);
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogError(ex, "SMS gateway request timed out for {Url}", url.GetLeftPart(UriPartial.Path));
            return (false, "تایم‌اوت اتصال به سرویس پیامک");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception while sending SMS: {Message}", ex.Message);
            return (false, "خطا در اتصال به سرویس پیامک");
        }
    }

    private static Uri BuildSendUrl(string sendUrl, string token, string num, string body)
    {
        var query = new StringBuilder(sendUrl.TrimEnd('?', '&'))
            .Append('?')
            .Append("Token=").Append(Uri.EscapeDataString(token))
            .Append("&Num=").Append(Uri.EscapeDataString(num))
            .Append("&Body=").Append(Uri.EscapeDataString(body));

        return new Uri(query.ToString());
    }

    private static bool IsAbruptGatewayClose(Exception ex)
    {
        for (var current = ex; current != null; current = current.InnerException)
        {
            if (current is IOException)
                return true;

            var message = current.Message;
            if (message.Contains("connection was closed", StringComparison.OrdinalIgnoreCase)
                || message.Contains("unexpectedly", StringComparison.OrdinalIgnoreCase)
                || message.Contains("prematurely", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
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
