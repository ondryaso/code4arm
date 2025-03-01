﻿// InstructionBreakpoint.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Serialization;

namespace Code4Arm.ExecutionCore.Protocol.Models;

public record InstructionBreakpoint
{
    /// <summary>
    /// The instruction reference of the breakpoint.
    /// This should be a memory or instruction pointer reference from an EvaluateResponse, Variable, StackFrame, GotoTarget, or
    /// Breakpoint.
    /// </summary>
    public string InstructionReference { get; init; }

    /// <summary>
    /// An optional offset from the instruction reference.
    /// This can be negative.
    /// </summary>
    [Optional]
    public int? Offset { get; init; }

    /// <summary>
    /// An optional expression for conditional breakpoints.
    /// It is only honored by a debug adapter if the capability 'supportsConditionalBreakpoints' is true.
    /// </summary>
    [Optional]
    public string? Condition { get; init; }

    /// <summary>
    /// An optional expression that controls how many hits of the breakpoint are ignored.
    /// The backend is expected to interpret the expression as needed.
    /// The attribute is only honored by a debug adapter if the capability 'supportsHitConditionalBreakpoints' is true.
    /// </summary>
    [Optional]
    public string? HitCondition { get; init; }
}
