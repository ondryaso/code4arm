using Code4Arm.ExecutionCore.Protocol.Serialization;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// Provides formatting information for a value.
/// </summary>
public record ValueFormat
{
    /// <summary>
    /// Display the value in hex.
    /// </summary>
    [Optional]
    public bool Hex { get; init; }
}
