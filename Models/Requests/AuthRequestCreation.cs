// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable MemberCanBePrivate.Global
using JsonPropertyAttribute = Newtonsoft.Json.JsonPropertyAttribute;
namespace KinoshitaProductions.AuthClient.Models.Requests
{
    internal class AuthRequestCreation
    {
        internal AuthRequestCreation(string appName, string? redirectUrl = null)
        {
            AppName = appName;
            RedirectUrl = redirectUrl;
        }
        [JsonProperty("appName")]
        public string AppName { get; set; }
        [JsonProperty("redirectUrl")]
        public string? RedirectUrl { get; set; }
    }
}
