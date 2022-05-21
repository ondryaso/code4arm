// ExpressionValueType.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public enum ExpressionValueType : uint
{
    ByteU = 0,
    ByteS,
    Default,
    ShortU,
    ShortS,
    IntU,
    IntS,
    LongU,
    LongS,
    Float,
    Double,
    String
}
