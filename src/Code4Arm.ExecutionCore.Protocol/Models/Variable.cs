﻿// Variable.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Serialization;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// A Variable is a name/value pair.
/// Optionally a variable can have a ‘type’ that is shown if space permits or when hovering over the variable’s name.
/// An optional ‘kind’ is used to render additional properties of the variable, e.g.different icons can be used to indicate
/// that a variable is public or private.
/// If the value is structured(has children), a handle is provided to retrieve the children with the VariablesRequest.
/// If the long of named or indexed children is large, the longs should be returned via the optional ‘namedVariables’ and
/// ‘indexedVariables’ attributes.
/// The client can use this optional information to present the children in a paged UI and fetch them in chunks.
/// </summary>
public record Variable
{
    /// <summary>
    /// The variable's name.
    /// </summary>
    public string Name { get; init; }

    /// <summary>
    /// The variable's value. This can be a multi-line text, e.g. for a function the body of a function.
    /// </summary>
    public string Value { get; init; }

    /// <summary>
    /// The type of the variable's value. Typically shown in the UI when hovering over the value.
    /// </summary>
    [Optional]
    public string? Type { get; init; }

    /// <summary>
    /// Properties of a variable that can be used to determine how to render the variable in the UI.
    /// </summary>
    [Optional]
    public VariablePresentationHint? PresentationHint { get; init; }

    /// <summary>
    /// Optional evaluatable name of this variable which can be passed to the 'EvaluateRequest' to fetch the variable's value.
    /// </summary>
    [Optional]
    public string? EvaluateName { get; init; }

    /// <summary>
    /// If variablesReference is > 0, the variable is structured and its children can be retrieved by passing
    /// variablesReference to the VariablesRequest.
    /// </summary>
    public long VariablesReference { get; init; }

    /// <summary>
    /// The long of named child variables.
    /// The client can use this optional information to present the children in a paged UI and fetch them in chunks.
    /// </summary>
    [Optional]
    public long? NamedVariables { get; init; }

    /// <summary>
    /// The long of indexed child variables.
    /// The client can use this optional information to present the children in a paged UI and fetch them in chunks.
    /// </summary>
    [Optional]
    public long? IndexedVariables { get; init; }

    /// <summary>
    /// Optional memory reference for the variable if the variable represents executable code, such as a function pointer.
    /// </summary>
    [Optional]
    public string? MemoryReference { get; init; }
}
