// ServiceOptions.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Execution.Configuration;

namespace Code4Arm.ExecutionService.Configuration;

public class ServiceOptions
{
    public AssemblerOptions AssemblerOptions { get; set; } = new();
    public LinkerOptions LinkerOptions { get; set; } = new();
    public ExecutionOptions DefaultExecutionOptions { get; set; } = new();
    public DebuggerOptions DefaultDebuggerOptions { get; set; } = new();

    public bool EnableCustomExecutionTimeout { get; set; }
    public bool EnableCustomStackSize { get; set; }
}
