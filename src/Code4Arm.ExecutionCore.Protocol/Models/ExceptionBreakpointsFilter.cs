// ExceptionBreakpointsFilter.cs
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
