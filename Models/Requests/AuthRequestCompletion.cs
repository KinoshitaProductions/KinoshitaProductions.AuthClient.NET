// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable MemberCanBePrivate.Global
using JsonPropertyAttribute = Newtonsoft.Json.JsonPropertyAttribute;
namespace KinoshitaProductions.AuthClient.Models.Requests
{
    internal class AuthRequestCompletion
    {
        internal AuthRequestCompletion(long requestId, string requestKey)
        {
            RequestId = requestId;
            RequestKey = requestKey;
        }
        [JsonProperty("requestId")]
        public long RequestId { get; set; }
        [JsonProperty("requestKey")]
        public string RequestKey { get; set; }
    }
}
