// MemorySegmentPermissions.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using System.Runtime.CompilerServices;
using Code4Arm.Unicorn.Abstractions.Enums;
using ELFSharp.ELF.Segments;

namespace Code4Arm.ExecutionCore.Assembling.Models;

[Flags]
public enum MemorySegmentPermissions
{
    None = 0,
    Read = 1,
    Write = 2,
    Execute = 4
}

public static class MemorySegmentPermissionsExtensions
{
    private static readonly MemorySegmentPermissions[] Lut =
    {
        MemorySegmentPermissions.None,
        MemorySegmentPermissions.Execute,
        MemorySegmentPermissions.Write,
        MemorySegmentPermissions.Write | MemorySegmentPermissions.Execute,
        MemorySegmentPermissions.Read,
        MemorySegmentPermissions.Read | MemorySegmentPermissions.Execute,
        MemorySegmentPermissions.Read | MemorySegmentPermissions.Write,
        MemorySegmentPermissions.Read | MemorySegmentPermissions.Write | MemorySegmentPermissions.Execute
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static MemoryPermissions ToUnicorn(this MemorySegmentPermissions permissions) =>
        (MemoryPermissions)permissions;

    public static MemorySegmentPermissions ToLocal(this SegmentFlags elfSegmentFlags) => Lut[(int)elfSegmentFlags];

    public static string ToFlagString(this MemorySegmentPermissions permissions)
        => (permissions.HasFlag(MemorySegmentPermissions.Read) ? "R" : "-")
            + (permissions.HasFlag(MemorySegmentPermissions.Write) ? "W" : "-")
            + (permissions.HasFlag(MemorySegmentPermissions.Execute) ? "E" : "-");
}
