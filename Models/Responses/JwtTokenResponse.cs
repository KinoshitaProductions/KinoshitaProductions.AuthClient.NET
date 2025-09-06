using System.IdentityModel.Tokens.Jwt;
using KinoshitaProductions.Common.Enums;
using KinoshitaProductions.Common.Interfaces.AppInfo;

namespace KinoshitaProductions.AuthClient.Models.Responses;

#pragma warning disable CS8618
using JsonPropertyAttribute = Newtonsoft.Json.JsonPropertyAttribute;

internal sealed class Token
{
    internal static Token? ParseTokenOrClearField(ref string? jwtToken, ref Token? tokenCache)
    {
        if (tokenCache != null) return tokenCache;
        if (jwtToken == null) return null;
        try
        {
            if (string.IsNullOrWhiteSpace(jwtToken))
                return null;
            var tokenHandler = new JwtSecurityTokenHandler();
            if (!tokenHandler.CanReadToken(jwtToken))
                return null;
            JwtSecurityToken parsedToken = tokenHandler.ReadJwtToken(jwtToken);
            var key = parsedToken.Claims.FirstOrDefault(claim => claim.Type == "key")?.Value;
            if (string.IsNullOrEmpty(key) || key.Length < 2)
                return null;
            JwtTokenKind kind = key[1] switch
            {
                'E' => JwtTokenKind.Elevated,
                'A' => JwtTokenKind.App,
                'S' => JwtTokenKind.Session,
                _ => JwtTokenKind.NotSpecified,
            };
            if (kind == JwtTokenKind.NotSpecified)
                return null;
            return tokenCache = new Token(kind, parsedToken.IssuedAt, parsedToken.ValidTo == DateTime.MinValue ? DateTime.MaxValue : parsedToken.ValidTo);
        } finally {
            if (tokenCache == null) jwtToken = null;
        }
    }
    private Token(JwtTokenKind kind, DateTime issuedAt, DateTime expirationDate)
    {
        Kind = kind;
        IssuedAt = issuedAt;
        ExpirationDate = expirationDate;
    }
    internal JwtTokenKind Kind { get; }
   // private JwtSecurityToken? _parsedValue;
    //internal JwtSecurityToken ParsedValue => _parsedValue ??= new JwtSecurityTokenHandler().ReadJwtToken(Value); // TODO: Must ensure we catch this, ideally when reading tokens
    private DateTime IssuedAt { get; }
    private DateTime ExpirationDate { get; }

    private TimeSpan Age => DateTime.UtcNow - IssuedAt;
    private TimeSpan StillValidFor => ExpirationDate - DateTime.UtcNow;
    private bool _isInvalid;
    internal bool IsValid => !_isInvalid && ExpirationDate > DateTime.UtcNow;
    internal bool NeedsRenewal => _needsRenewal || Age > TimeSpan.FromDays(3) || StillValidFor < TimeSpan.FromDays(7);
    private bool _needsRenewal;
    internal void FlagForRenewal(bool needsRenewal, bool isInvalid = false)
    {
        _needsRenewal = needsRenewal;
        _isInvalid = isInvalid;
    }
}

internal class JwtCredentialsStore
{    
    private IJwtAuthenticatedServiceAppInfo? _appInfo;
    public void LinkToAppInfo(IJwtAuthenticatedServiceAppInfo appInfo)
    {
        _appInfo = appInfo;
    }
    [JsonProperty("et")]
    internal string? ElevatedToken
    {
        get => _elevatedToken;
        set { if (_elevatedToken != value) { _elevatedToken = value; _elevatedTokenCache = null; } }
    }

    private string? _elevatedToken;

    private Token? _elevatedTokenCache;

    [JsonProperty("at")]
    internal string? AppToken
    {
        get => _appToken;
        set { if (_appToken != value) { _appToken = value; _appTokenCache = null; } }
    }
    private string? _appToken;

    private Token? _appTokenCache;

    [JsonProperty("st")]
    internal string? SessionToken
    {
        get => _sessionToken;
        set { if (_sessionToken != value) { _sessionToken = value; _sessionTokenCache = null; } }
    }
    private string? _sessionToken;
    private Token? _sessionTokenCache;

    public bool HasToken(JwtTokenKind kind) => GetToken(kind)?.IsValid == true;
    public Token? GetToken(JwtTokenKind kind) =>
        kind switch
        {
            JwtTokenKind.Elevated => Token.ParseTokenOrClearField(ref _elevatedToken, ref _elevatedTokenCache),
            JwtTokenKind.App => Token.ParseTokenOrClearField(ref _appToken, ref _appTokenCache),
            JwtTokenKind.Session => Token.ParseTokenOrClearField(ref _sessionToken, ref _sessionTokenCache),
            _ => throw new ArgumentException($"Invalid token kind {kind} specified"),
        };
    
    internal JwtCredentialsStore WithoutElevatedTokenForStoring()
    {
        return new JwtCredentialsStore
        {
            _appToken = _appToken,
            _sessionToken = _sessionToken,
        };
    }
    public void MergeTokensFrom(JwtCredentialsStore merging)
    {
        ElevatedToken = merging.ElevatedToken ?? ElevatedToken;
        AppToken = merging.AppToken ?? AppToken;
        SessionToken = merging.SessionToken ?? SessionToken;
        _appInfo?.SetJwtAuthenticationCredentials(ElevatedToken, AppToken, SessionToken);
    }

    public JwtCredentialsStore Sanitize()
    {
        GetToken(JwtTokenKind.Elevated);
        GetToken(JwtTokenKind.App);
        GetToken(JwtTokenKind.Session);
        return this;
    }

    public void Clear()
    {
        _elevatedToken = null;
        _elevatedTokenCache = null;
        _appToken = null;
        _appTokenCache = null;
        _sessionToken = null;
        _sessionTokenCache = null;
    }
}
// currently these two share the scheme for JSON fully
internal sealed class JwtTokenResponse : JwtCredentialsStore
{
}
