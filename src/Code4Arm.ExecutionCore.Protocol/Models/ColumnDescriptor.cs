﻿// ColumnDescriptor.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

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
