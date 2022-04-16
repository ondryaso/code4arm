// MemorySegmentPermissions.cs
// Author: Ondřej Ondryáš

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
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static MemoryPermissions ToUnicorn(this MemorySegmentPermissions permissions)
    {
        return (MemoryPermissions) permissions;
    }

    private static readonly MemorySegmentPermissions[] Lut = new[]
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

    public static MemorySegmentPermissions ToLocal(this SegmentFlags elfSegmentFlags)
    {
        return Lut[(int) elfSegmentFlags];
    }
}