namespace KinoshitaProductions.AuthClient.Models.Responses;

#pragma warning disable CS8618
using JsonPropertyAttribute = Newtonsoft.Json.JsonPropertyAttribute;

internal class JwtTokenResponse
{
    public JwtTokenResponse() {}
    [JsonProperty("et")]
    public string? ElevatedToken { get; set; }
    [JsonProperty("eted")]
    public DateTime? ElevatedTokenExpirationDate { get; set; }
    [JsonProperty("at")]
    public string AppToken { get; set; }
    [JsonProperty("aed")]
    public DateTime? AppTokenExpirationDate { get; set; }
    [JsonProperty("st")]
    public string? SessionToken { get; set; }
    [JsonProperty("sted")]
    public DateTime? SessionTokenExpirationDate { get; set; }

    internal JwtTokenResponse WithoutElevatedToken()
    {
        return new JwtTokenResponse
        {
            AppToken = this.AppToken,
            AppTokenExpirationDate = this.AppTokenExpirationDate,
            SessionToken = this.SessionToken,
            SessionTokenExpirationDate = this.SessionTokenExpirationDate,
        };
    }
}
