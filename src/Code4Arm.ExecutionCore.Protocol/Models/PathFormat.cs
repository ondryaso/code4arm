using Code4Arm.ExecutionCore.Protocol.StringEnum;

namespace Code4Arm.ExecutionCore.Protocol.Models;

public class PathFormat : StringEnum<PathFormat>
{
    public static readonly PathFormat Path = Create("path");
    public static readonly PathFormat Uri = Create("uri");
}
