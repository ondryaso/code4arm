// EnumExtensions.cs
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

using System;

namespace Code4Arm.LanguageServer.Extensions;

public static class EnumExtensions
{
    /// <summary>
    /// Converts the string representation of the name of an enumerated constant to an equivalent enumerated object.
    /// In contrast to <see cref="Enum.TryParse{TEnum}(string,bool,out TEnum)"/>, this will only be successful
    /// for a string that contains one of the names defined in the enum, and not for any integer number.
    /// </summary>
    /// <param name="input">The string representation of the enumeration name or underlying value to convert.</param>
    /// <param name="result">When this method returns, result contains an object of type <typeparamref name="TEnum"/>
    /// whose value is represented by the input string if the parse operation succeeds. If the parse operation fails,
    /// result contains the default value of the underlying type of TEnum. This value is a member of the
    /// <typeparamref name="TEnum"/> enumeration. This parameter is passed uninitialized.</param>
    /// <typeparam name="TEnum">The enumeration type to which to convert value.</typeparam>
    /// <returns>True if the conversion succeeded.</returns>
    public static bool TryParseName<TEnum>(string input, out TEnum result) where TEnum : struct
    {
        var type = typeof(TEnum);
        return Enum.TryParse(input, true, out result) &&
               (Enum.GetName(type, result)?.Equals(input, StringComparison.InvariantCultureIgnoreCase) ??
                false);
    }
}
