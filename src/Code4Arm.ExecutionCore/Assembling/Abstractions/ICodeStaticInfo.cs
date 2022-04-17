// ICodeStaticInfo.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.DebugAdapter.Protocol.Models;
using OmniSharp.Extensions.DebugAdapter.Protocol.Requests;

namespace Code4Arm.ExecutionCore.Assembling.Abstractions;

public interface ICodeStaticInfo
{
    IEnumerable<BreakpointLocation> GetBreakpointLocations(BreakpointLocationsArguments arguments);
    IEnumerable<DisassembledInstruction> Disassemble(DisassembleArguments arguments);
}
