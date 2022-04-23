// StackFrame.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Serialization;
using Code4Arm.ExecutionCore.Protocol.StringEnum;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// A Stackframe contains the source location.
/// </summary>
public record StackFrame
{
    /// <summary>
    /// An identifier for the stack frame. It must be unique across all threads. This id can be used to retrieve the scopes of
    /// the frame with the 'scopesRequest' or to restart the
    /// execution of a stackframe.
    /// </summary>
    public long Id { get; init; }

    /// <summary>
    /// The name of the stack frame, typically a method name.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// The optional source of the frame.
    /// </summary>
    [Optional]
    public Source? Source { get; init; }

    /// <summary>
    /// The line within the file of the frame. If source is null or doesn't exist, line is 0 and must be ignored.
    /// </summary>
    public int Line { get; init; }

    /// <summary>
    /// The column within the line. If source is null or doesn't exist, column is 0 and must be ignored.
    /// </summary>
    public int Column { get; init; }

    /// <summary>
    /// An optional end line of the range covered by the stack frame.
    /// </summary>
    [Optional]
    public int? EndLine { get; init; }

    /// <summary>
    /// An optional end column of the range covered by the stack frame.
    /// </summary>
    [Optional]
    public int? EndColumn { get; init; }

    /// <summary>
    /// Optional memory reference for the current instruction pointer in this frame.
    /// </summary>
    [Optional]
    public string? InstructionPointerReference { get; init; }

    /// <summary>
    /// The module associated with this frame, if any.
    /// </summary>
    [Optional]
    public NumberString? ModuleId { get; init; }

    /// <summary>
    /// An optional hint for how to present this frame in the UI. A value of 'label' can be used to indicate that the frame is
    /// an artificial frame that is used as a visual label or
    /// separator. A value of 'subtle' can be used to change the appearance of a frame in a 'subtle' way.
    /// </summary>
    [Optional]
    public StackFramePresentationHint? PresentationHint { get; init; }
    
    /// <summary>
    /// Indicates whether this frame can be restarted with the 'restart' request.
    /// Clients should only use this if the debug adapter supports the 'restart'
    /// request (capability 'supportsRestartRequest' is true).
    /// </summary>
    [Optional]
    public bool CanRestart { get; init; }
}

public class StackFramePresentationHint : StringEnum<StackFramePresentationHint>
{
    public static readonly StackFramePresentationHint Normal = Create("normal");
    public static readonly StackFramePresentationHint Label = Create("label");
    public static readonly StackFramePresentationHint Subtle = Create("subtle");
}
