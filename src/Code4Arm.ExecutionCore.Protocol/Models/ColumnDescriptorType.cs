using Code4Arm.ExecutionCore.Protocol.StringEnum;

namespace Code4Arm.ExecutionCore.Protocol.Models;

public class ColumnDescriptorType : StringEnum<ColumnDescriptorType>
{
    public static readonly ColumnDescriptorType String = Create("string");
    public static readonly ColumnDescriptorType Long = Create("long");
    public static readonly ColumnDescriptorType Bool = Create("boolean");
    public static readonly ColumnDescriptorType UnixTimestampUtc = Create("unixTimestampUTC");
}
