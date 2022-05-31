// OptionChangeBehaviorAttribute.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Configuration;

/// <summary>
/// Determines the behaviour expected when changing a certain option of the execution engine.
/// </summary>
public enum OptionChangeBehavior
{
    /// <summary>
    /// No special behaviour is needed.
    /// </summary>
    None,

    /// <summary>
    /// When changing the option, the executable should be reloaded.
    /// </summary>
    ReloadExecutable,

    /// <summary>
    /// When changing the option, a new instance of the engine must be created.
    /// </summary>
    RecreateEngine
}

/// <summary>
/// Applies an <see cref="OptionChangeBehavior"/> on an execution engine configuration property.
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public class OptionChangeBehaviorAttribute : Attribute
{
    public OptionChangeBehavior Behavior { get; }

    public OptionChangeBehaviorAttribute(OptionChangeBehavior behavior)
    {
        Behavior = behavior;
    }
}
