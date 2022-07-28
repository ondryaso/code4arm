// DataBreakpoint.cs
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
/// Properties of a data breakpoint passed to the setDataBreakpoints request.
/// </summary>
public record DataBreakpoint
{
    /// <summary>
    /// An id representing the data. This id is returned from the dataBreakpointInfo request.
    /// </summary>
    public string DataId { get; init; }

    /// <summary>
    /// The access type of the data.
    /// </summary>
    [Optional]
    public DataBreakpointAccessType? AccessType { get; init; }

    /// <summary>
    /// An optional expression for conditional breakpoints.
    /// </summary>
    [Optional]
    public string? Condition { get; init; }

    /// <summary>
    /// An optional expression that controls how many hits of the breakpoint are ignored. The backend is expected to interpret
    /// the expression as needed.
    /// </summary>
    [Optional]
    public string? HitCondition { get; init; }
}
