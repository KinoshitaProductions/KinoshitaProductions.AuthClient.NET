// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedMember.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global
#pragma warning disable CS8618
using JsonPropertyAttribute = Newtonsoft.Json.JsonPropertyAttribute;
namespace KinoshitaProductions.AuthClient.Models.Responses
{
    public class AuthRequestCreated
    {
        [JsonProperty("requestId")]
        public long RequestId { get; set; }
        [JsonProperty("requestKey")]
        public string RequestKey { get; set; }
        [JsonProperty("checkKey")]
        public string CheckKey { get; set; }
    }
}
