// EnumExtensions.cs
// Author: Ondřej Ondryáš

using System;

namespace Armfors.LanguageServer.Extensions;

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
