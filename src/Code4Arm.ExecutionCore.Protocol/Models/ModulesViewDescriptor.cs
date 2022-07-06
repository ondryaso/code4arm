// ModulesViewDescriptor.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// The ModulesViewDescriptor is the container for all declarative configuration options of a ModuleView.
/// For now it only specifies the columns to be shown in the modules view.
/// </summary>
public record ModulesViewDescriptor
{
    public Container<ColumnDescriptor> Columns { get; init; }
}
