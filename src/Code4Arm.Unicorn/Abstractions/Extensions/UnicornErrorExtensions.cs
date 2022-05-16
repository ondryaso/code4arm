// UnicornErrorExtensions.cs
// Author: Ondřej Ondryáš

using Code4Arm.Unicorn.Abstractions.Enums;

namespace Code4Arm.Unicorn.Abstractions.Extensions;

public static class UnicornErrorExtensions
{
    public static bool IsMemoryError(this UnicornError error)
        => error is UnicornError.FetchProtected or UnicornError.FetchUnaligned or UnicornError.FetchUnmapped
            or UnicornError.ReadProtected or UnicornError.ReadUnaligned or UnicornError.ReadUnmapped
            or UnicornError.WriteProtected or UnicornError.WriteUnaligned or UnicornError.WriteUnmapped;

    public static bool IsMemoryUnmappedError(this UnicornError error)
        => error is UnicornError.FetchUnmapped or UnicornError.ReadUnmapped or UnicornError.WriteUnmapped;

    public static bool IsMemoryUnalignedError(this UnicornError error)
        => error is UnicornError.FetchUnaligned or UnicornError.ReadUnaligned or UnicornError.WriteUnaligned;

    public static bool IsMemoryProtectedError(this UnicornError error)
        => error is UnicornError.FetchProtected or UnicornError.ReadProtected or UnicornError.WriteProtected;

    public static bool IsMemoryFetchError(this UnicornError error)
        => error is UnicornError.FetchProtected or UnicornError.FetchUnaligned or UnicornError.FetchUnmapped;

    public static bool IsMemoryReadError(this UnicornError error)
        => error is UnicornError.ReadProtected or UnicornError.ReadUnaligned or UnicornError.ReadUnmapped;

    public static bool IsMemoryWriteError(this UnicornError error)
        => error is UnicornError.WriteProtected or UnicornError.WriteUnaligned or UnicornError.WriteUnmapped;
}
