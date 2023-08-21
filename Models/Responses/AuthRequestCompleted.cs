// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global
#pragma warning disable CS8618
using JsonPropertyAttribute = Newtonsoft.Json.JsonPropertyAttribute;
namespace KinoshitaProductions.AuthClient.Models.Responses
{
    internal class AuthRequestCompleted
    {
        public AuthRequestCompleted() {}
        [JsonProperty("token")]
        public string Token { get; set; }
    }
}
