// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable MemberCanBePrivate.Global
using JsonPropertyAttribute = Newtonsoft.Json.JsonPropertyAttribute;
namespace KinoshitaProductions.AuthClient.Models.Requests
{
    internal class AuthRequestCheck
    {
        internal AuthRequestCheck(long requestId, string checkKey)
        {
            RequestId = requestId;
            CheckKey = checkKey;
        }
        [JsonProperty("requestId")]
        public long RequestId { get; set; }
        [JsonProperty("checkKey")]
        public string CheckKey { get; set; }
    }
}
