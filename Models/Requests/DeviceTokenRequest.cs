using JsonPropertyAttribute = Newtonsoft.Json.JsonPropertyAttribute;
namespace KinoshitaProductions.AuthClient.Models.Requests;

internal class DeviceTokenRequest
{
    internal DeviceTokenRequest(long deviceId)
    {
        DeviceId = deviceId;
    }
    [JsonProperty("i")]
    public long DeviceId { get; set; }
}