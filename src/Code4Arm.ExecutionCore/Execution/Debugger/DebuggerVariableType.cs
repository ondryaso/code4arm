// DebuggerVariableType.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public enum DebuggerVariableType : uint
{
    ByteU = 0,
    ByteS,
    CharAscii,
    ShortU,
    ShortS,
    IntU,
    IntS,
    LongU,
    LongS,
    Float,
    Double
}
