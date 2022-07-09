// Utils.cs
// Author: Ondřej Ondryáš

namespace GrammarMaker;

public static class Utils
{
    public static string FindLongestPrefix(List<string> strings)
    {
        int size = strings.Count;

        if (size == 0)
            return "";

        if (size == 1)
            return strings[0];

        strings.Sort();

        var end = Math.Min(strings[0].Length,
            strings[size - 1].Length);

        var i = 0;
        while (i < end && strings[0][i] == strings[size - 1][i])
            i++;

        var pre = strings[0].Substring(0, i);

        return pre;
    }

    public static string FindLongestPrefix(string a, string b)
    {
        if (string.Compare(a, b, StringComparison.Ordinal) > 0)
        {
            (a, b) = (b, a);
        }

        var end = Math.Min(a.Length,
            b.Length);

        var i = 0;
        while (i < end && a[i] == b[i])
        {
            i++;
        }

        var pre = a.Substring(0, i);

        return pre;
    }

    public static IEnumerable<IGrouping<string, T>> GroupByLongestPrefix<T>(this List<T> list,
        Func<T, string> keySelector)
    {
        var longestPrefix = new Dictionary<string, string>();

        if (list.Count == 1)
            return list.GroupBy(keySelector); 
                
        for (var i = 0; i != list.Count; i++)
        {
            for (var j = i + 1; j != list.Count; j++)
            {
                var keyA = keySelector(list[i]);
                var keyB = keySelector(list[j]);

                var common = FindLongestPrefix(keyA, keyB);
                AddLongest(longestPrefix, keyA, common);
                AddLongest(longestPrefix, keyB, common);
            }
        }

        return list.GroupBy(x => longestPrefix[keySelector(x)]);
    }

    public static IEnumerable<IGrouping<string, string>> GroupByLongestPrefix(this List<string> list)
    {
        var longestPrefix = new Dictionary<string, string>();
        for (var i = 0; i != list.Count; i++)
        {
            for (var j = i + 1; j != list.Count; j++)
            {
                var keyA = list[i];
                var keyB = list[j];

                var common = FindLongestPrefix(keyA, keyB);
                AddLongest(longestPrefix, keyA, common);
                AddLongest(longestPrefix, keyB, common);
            }
        }

        return list.GroupBy(x => longestPrefix[x]);
    }

    private static void AddLongest(IDictionary<string, string> dict, string s, string p)
    {
        if (!dict.TryGetValue(s, out var current) || p.Length > current.Length)
            dict[s] = p;
    }
}