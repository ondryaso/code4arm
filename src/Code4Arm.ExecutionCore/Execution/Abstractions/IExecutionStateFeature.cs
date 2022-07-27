// IExecutionStateFeature.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

/// <summary>
/// Represents an additional 'state feature' of an <see cref="IExecutionEngine"/> instance.
/// These may be used to provide additional simulated features for the emulated programs that are not crucial for the
/// emulation itself.
/// </summary>
public interface IExecutionStateFeature
{
}
