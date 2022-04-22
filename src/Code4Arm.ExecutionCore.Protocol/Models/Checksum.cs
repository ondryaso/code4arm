using Newtonsoft.Json;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// The checksum of an item calculated by the specified algorithm.
/// </summary>
public record Checksum
{
    /// <summary>
    /// The algorithm used to calculate this checksum.
    /// </summary>
    public ChecksumAlgorithm Algorithm { get; init; }

    /// <summary>
    /// Value of the checksum.
    /// </summary>
    [JsonProperty("checksum")]
    public string Value { get; init; }
}
