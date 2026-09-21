using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using SSOLoginService.Web.Services;

namespace SSOLoginService.Web.Controllers;

/// <summary>
/// JSON API for citizen apps (137 web/mobile). OTP SMS is sent server-side like the login portal.
/// </summary>
[ApiController]
[Route("api/auth")]
public class AuthApiController : ControllerBase
{
    private readonly OtpDeliveryService _otpDelivery;

    public AuthApiController(OtpDeliveryService otpDelivery)
    {
        _otpDelivery = otpDelivery;
    }

    [HttpPost("second-login/send-otp")]
    [EnableCors("CitizenApps")]
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
