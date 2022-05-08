// Utils.cs
// Author: Ondřej Ondryáš

using System.Reflection;

namespace Code4Arm.ExecutionCore;

public static class Utils
{
    public static string GetSupportFile(string fileName)
    {
        var assemblyFile = new Uri(Assembly.GetExecutingAssembly().Location).LocalPath;
        var assemblyDir = Path.GetDirectoryName(assemblyFile);

        if (assemblyDir == null)
            return Path.Combine("SupportFiles", fileName);

        return Path.Combine(assemblyDir, "SupportFiles", fileName);
    }
}
