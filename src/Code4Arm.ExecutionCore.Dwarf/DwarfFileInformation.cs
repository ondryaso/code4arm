// DwarfFileInformation.cs
// Original source: https://github.com/southpolenator/SharpDebug
// Original author: Vuk Jovanovic
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) 2019 Vuk Jovanovic, 2022 Ondřej Ondryáš.

namespace Code4Arm.ExecutionCore.Dwarf;

/// <summary>
/// File metadata with line information
/// </summary>
public class DwarfFileInformation
{
    /// <summary>
    /// Gets or sets the file name.
    /// </summary>
    public string Name { get; init; }

    /// <summary>
    /// Gets or sets the directory.
    /// </summary>
    public string Directory { get; init; }

    /// <summary>
    /// Gets or sets the path.
    /// </summary>
    public string Path { get; init; }

    /// <summary>
    /// Gets or sets the last modification.
    /// </summary>
    public uint LastModification { get; init; }

    /// <summary>
    /// Gets or sets the length.
    /// </summary>
    public uint Length { get; init; }

    /// <summary>
    /// Gets or sets the lines information.
    /// </summary>
    public List<DwarfLineInformation> Lines { get; } = new();

    /// <summary>
    /// Returns a <see cref="System.String"/> that represents this instance.
    /// </summary>
    /// <returns>
    /// A <see cref="System.String"/> that represents this instance.
    /// </returns>
    public override string ToString() => Name;
}
