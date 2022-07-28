// Variable.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// 
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// Copyright (c) .NET Foundation and Contributors
// All Rights Reserved
// 
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Available under the MIT License.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
// to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of
// the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
