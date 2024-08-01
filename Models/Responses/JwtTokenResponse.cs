using System.IdentityModel.Tokens.Jwt;
using KinoshitaProductions.Common.Enums;
using KinoshitaProductions.Common.Interfaces.AppInfo;
using Serilog;

namespace KinoshitaProductions.AuthClient.Models.Responses;

#pragma warning disable CS8618
using JsonPropertyAttribute = Newtonsoft.Json.JsonPropertyAttribute;

internal sealed class Token
{
    internal Token(JwtTokenKind kind, string value)
    {
        Kind = kind;
        Value = value;
    }
    internal JwtTokenKind Kind { get; }
    internal string Value { get; }
    private JwtSecurityToken? _parsedValue;
    internal JwtSecurityToken ParsedValue => _parsedValue ??= new JwtSecurityTokenHandler().ReadJwtToken(Value); // TODO: Must ensure we catch this, ideally when reading tokens
    internal DateTime ExpirationDate
    {
        get
        {
            var expirationDate = ParsedValue.ValidTo;
            return expirationDate == DateTime.MinValue ? DateTime.MaxValue : expirationDate;
        }
    }

    private TimeSpan Age => DateTime.UtcNow - ParsedValue.IssuedAt;
    private TimeSpan StillValidFor => ParsedValue.ValidTo - DateTime.UtcNow;
    internal bool IsValid => ParsedValue.ValidTo > DateTime.UtcNow;
    internal bool ShouldConsiderRenewal => _needsRenewal || Age > TimeSpan.FromDays(7) || StillValidFor < TimeSpan.FromDays(7);
    private bool _needsRenewal;
    internal void FlagForRenewal()
    {
        _needsRenewal = true;
    }
}

internal sealed class JwtTokenResponse
{
    public JwtTokenResponse() {}

    public JwtTokenResponse(IJwtAuthenticatedServiceAppInfo appInfo)
    {
        _appInfo = appInfo;
    }

    private readonly IJwtAuthenticatedServiceAppInfo? _appInfo;
    private readonly Token?[] _tokenCache = new Token?[4];
    public bool HasToken(JwtTokenKind kind) => GetToken(kind)?.IsValid == true;
    public Token? GetToken(JwtTokenKind kind)
    {
        var value = kind switch
        {
            JwtTokenKind.Elevated => ElevatedToken,
            JwtTokenKind.App => AppToken,
            JwtTokenKind.Session => SessionToken,
            _ => throw new ArgumentException($"Invalid token kind {kind} specified"),
        };
        return value == null ? null : _tokenCache[(int)kind] ??= new Token(kind, value);
    }

    public bool CanRead()
    {
        try
        {
            foreach (var token in _tokenCache) _ = token?.ParsedValue;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to read one of the stored tokens");
            return false;
        }
        return true;
    }

    public void MergeTokensFrom(JwtTokenResponse response)
    {
        ElevatedToken = response.ElevatedToken ?? ElevatedToken;
        AppToken = response.AppToken ?? AppToken;
        SessionToken = response.SessionToken ?? SessionToken;
        for (var i = 0; i < _tokenCache.Length; ++i) _tokenCache[i] = null;
        _appInfo?.SetJwtAuthenticationCredentials(ElevatedToken, AppToken, SessionToken);
    }
    public async Task ClearTokens()
    {
        if (_appInfo != null)
            await _appInfo.ClearAuthenticationCredentials().ConfigureAwait(false);
        for (var i = 0; i < _tokenCache.Length; ++i) _tokenCache[i] = null;
    }
    [JsonProperty("et")]
    public string? ElevatedToken { get; set; }
    [JsonProperty("at")]
    public string? AppToken { get; set; }
    [JsonProperty("st")]
    public string? SessionToken { get; set; }

    internal JwtTokenResponse WithoutElevatedToken()
    {
        return new JwtTokenResponse
        {
            AppToken = AppToken,
            SessionToken = SessionToken,
        };
    }
}
