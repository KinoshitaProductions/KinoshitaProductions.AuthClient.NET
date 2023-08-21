// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedMember.Global
#pragma warning disable CS8618
using JsonPropertyAttribute = Newtonsoft.Json.JsonPropertyAttribute;
namespace KinoshitaProductions.AuthClient.Models.Responses
{
    public class AuthRequestChecked
    {
        [JsonProperty("foundWaiting")]
        public bool FoundWaiting { get; set; }
    }
}
