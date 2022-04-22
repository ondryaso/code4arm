using Code4Arm.ExecutionCore.Protocol.StringEnum;

namespace Code4Arm.ExecutionCore.Protocol.Models;

public class InvalidatedAreas : StringEnum<InvalidatedAreas>
{
    public static readonly InvalidatedAreas All = Create("all");
    public static readonly InvalidatedAreas Stacks = Create("stacks");
    public static readonly InvalidatedAreas Threads = Create("threads");
    public static readonly InvalidatedAreas Variables = Create("variables");
}
