// EnumerableExtensions.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionService.Extensions;

public static class EnumerableExtensions
{
    public static bool SequenceOrNullEqual<T>(this IEnumerable<T>? a, IEnumerable<T>? b)
    {
        if ((a == null && b != null) || (a != null && b == null))
            return false;

        return ReferenceEquals(a, b) || a!.SequenceEqual(b!);
    }
}
