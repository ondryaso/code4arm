// ExceptionDetails.cs
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
/// ExceptionDetails
/// Detailed information about an exception that has occurred.
/// </summary>
public record ExceptionDetails
{
    /// <summary>
    /// Message contained in the exception.
    /// </summary>
    [Optional]
    public string? Message { get; init; }

    /// <summary>
    /// Short type name of the exception object.
    /// </summary>
    [Optional]
    public string? TypeName { get; init; }

    /// <summary>
    /// Fully-qualified type name of the exception object.
    /// </summary>
    [Optional]
    public string? FullTypeName { get; init; }

    /// <summary>
    /// Optional expression that can be evaluated in the current scope to obtain the exception object.
    /// </summary>
    [Optional]
    public string? EvaluateName { get; init; }

    /// <summary>
    /// Stack trace at the time the exception was thrown.
    /// </summary>
    [Optional]
    public string? StackTrace { get; init; }

    /// <summary>
    /// Details of the exception contained by this exception, if any.
    /// </summary>
    [Optional]
    public Container<ExceptionDetails>? InnerException { get; init; }
}
