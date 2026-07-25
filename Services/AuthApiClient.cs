using System.Net.Http.Json;
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

public class ExchangeCodeResponse
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

public class ApiResult<T>
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("data")]
    public T? Data { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }
}

public class AuthApiClient
{
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
            var result = await response.Content.ReadFromJsonAsync<ApiResult<ExchangeCodeResponse>>();

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
}
