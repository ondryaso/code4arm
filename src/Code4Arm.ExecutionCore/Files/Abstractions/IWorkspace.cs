// IWorkspace.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Files.Abstractions;

public interface IWorkspace
{
    /// <summary>
    /// Returns an enumerable of workspace files in linking order.
    /// </summary>
    IEnumerable<IAsmFile> GetFiles();

    /// <summary>
    /// Returns a workspace file of given <paramref name="name"/>.
    /// </summary>
    /// <param name="name">The name of the workspace file.</param>
    /// <returns>The workspace ASM file or null if no such file exists.</returns>
    IAsmFile? GetFile(string name);
}
