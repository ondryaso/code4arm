using Code4Arm.ExecutionCore.Protocol.Serialization;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// ExceptionBreakpointsFilter
/// An ExceptionBreakpointsFilter is shown in the UI as an option for configuring how exceptions are dealt with.
/// </summary>
public record ExceptionBreakpointsFilter
{
    /// <summary>
    /// The internal ID of the filter. This value is passed to the setExceptionBreakpoints request.
    /// </summary>
    public string Filter { get; init; }

    /// <summary>
    /// The name of the filter. This will be shown in the UI.
    /// </summary>
    public string Label { get; init; }

    /// <summary>
    /// Initial value of the filter. If not specified a value 'false' is assumed.
    /// </summary>
    [Optional]
    public bool Default { get; init; }

    /// <summary>
    /// Controls whether a condition can be specified for this filter option. If
    /// false or missing, a condition can not be set.
    /// </summary>
    [Optional]
    public bool SupportsCondition { get; init; }
    
    /// <summary>
    /// An optional help text providing additional information about the exception
    /// filter. This string is typically shown as a hover and must be translated.
    /// </summary>
    [Optional]
    public string? Description { get; init; }
    
    /// <summary>
    /// An optional help text providing information about the condition. This
    /// string is shown as the placeholder text for a text box and must be
    /// translated.
    /// </summary>
    [Optional]
    public string? ConditionDescription { get; init; }
}
