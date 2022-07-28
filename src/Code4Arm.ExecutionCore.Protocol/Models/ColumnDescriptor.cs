// ColumnDescriptor.cs
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
/// A ColumnDescriptor specifies what module attribute to show in a column of the ModulesView, how to format it, and what
/// the column’s label should be.
/// It is only used if the underlying UI actually supports this level of customization.
/// </summary>
public record ColumnDescriptor
{
    /// <summary>
    /// Name of the attribute rendered in this column.
    /// </summary>
    public string AttributeName { get; init; }

    /// <summary>
    /// Header UI label of column.
    /// </summary>
    public string Label { get; init; }

    /// <summary>
    /// Format to use for the rendered values in this column. TBD how the format strings looks like.
    /// </summary>
    [Optional]
    public string? Format { get; init; }

    /// <summary>
    /// Datatype of values in this column.  Defaults to 'string' if not specified.
    /// </summary>
    [Optional]
    public ColumnDescriptorType? Type { get; init; }

    /// <summary>
    /// Width of this column in characters (hint only).
    /// </summary>
    [Optional]
    public long? Width { get; init; }
}
