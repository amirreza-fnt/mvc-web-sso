using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using SSOLoginService.Web.Services;

namespace SSOLoginService.Web.Controllers;

/// <summary>
/// Citizen apps (137). OTP SMS like the login portal. Routes must differ from
/// <see cref="AuthApiClient"/> login API paths to avoid self-call SMS loops.
/// </summary>
[ApiController]
[Route("api/citizen")]
[EnableCors("CitizenApps")]
public class AuthApiController : ControllerBase
{
    private readonly OtpDeliveryService _otpDelivery;
    private readonly ILogger<AuthApiController> _logger;

    public AuthApiController(OtpDeliveryService otpDelivery, ILogger<AuthApiController> logger)
    {
        _otpDelivery = otpDelivery;
        _logger = logger;
    }

    [HttpPost("send-login-otp")]
    public async Task<ActionResult<ApiResult<object>>> SendOtp([FromBody] CitizenSendOtpRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.PhoneNumber) || string.IsNullOrWhiteSpace(request.MelliCode))
        {
            return BadRequest(new ApiResult<object>
            {
                Success = false,
                Message = "شماره تلفن و کد ملی الزامی است"
            });
        }

        _logger.LogInformation(
            "Citizen send-login-otp from {RemoteIp}",
            HttpContext.Connection.RemoteIpAddress);

        var (ok, error) = await _otpDelivery.SendOtpWithSmsAsync(
            request.PhoneNumber.Trim(),
            request.MelliCode.Trim());

        if (!ok)
        {
            return BadRequest(new ApiResult<object>
            {
                Success = false,
                Message = error ?? "ارسال کد تایید ناموفق بود"
            });
        }

        return Ok(new ApiResult<object>
        {
            Success = true,
            Data = new { message = "کد تایید ارسال شد" }
        });
    }
}

public class CitizenSendOtpRequest
{
    [JsonPropertyName("phoneNumber")]
    public string PhoneNumber { get; set; } = string.Empty;

    [JsonPropertyName("melliCode")]
    public string MelliCode { get; set; } = string.Empty;

    [JsonPropertyName("phoneId")]
    public int? PhoneId { get; set; }
}
