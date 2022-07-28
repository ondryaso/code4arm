// UnicornErrorExtensions.cs
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
