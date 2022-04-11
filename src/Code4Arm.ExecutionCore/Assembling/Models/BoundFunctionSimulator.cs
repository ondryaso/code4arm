// BoundFunctionSimulator.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;

namespace Code4Arm.ExecutionCore.Assembling.Models;

public record struct BoundFunctionSimulator(IFunctionSimulator FunctionSimulator, uint Address);
