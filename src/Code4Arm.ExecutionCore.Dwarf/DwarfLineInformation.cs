// DwarfLineInformation.cs
// Original source: https://github.com/southpolenator/SharpDebug
// Original author: Vuk Jovanovic
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) 2019 Vuk Jovanovic, 2022 Ondřej Ondryáš.

namespace Code4Arm.ExecutionCore.Dwarf;

/// <summary>
/// Information about line containing compiled code.
/// </summary>
public record struct DwarfLineInformation
{
    /// <summary>
    /// Gets or sets the file information.
    /// </summary>
    public DwarfFileInformation File { get; init; }

    /// <summary>
    /// Gets or sets the relative module address.
    /// </summary>
    public uint Address { get; init; }

    /// <summary>
    /// Gets or sets the line.
    /// </summary>
    public uint Line { get; init; }

    /// <summary>
    /// Gets or sets the column.
    /// </summary>
    public uint Column { get; init; }
}
