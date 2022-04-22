// ICodeStaticInfo.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;

namespace Code4Arm.ExecutionCore.Assembling.Abstractions;

public interface ICodeStaticInfo
{
    IEnumerable<BreakpointLocation> GetBreakpointLocations(BreakpointLocationsArguments arguments);
    IEnumerable<DisassembledInstruction> Disassemble(DisassembleArguments arguments);
}
