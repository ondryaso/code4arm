using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Code4Arm.ExecutionCore.Protocol.Models;

[JsonConverter(typeof(StringEnumConverter))]
public enum SteppingGranularity
{
    Statement,
    Line,
    Instruction
}
