// IAsmMakeTarget.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Files.Abstractions;

/// <summary>
/// An abstraction over a set of assembly source files that are assembled and linked together.
/// </summary>
public interface IAsmMakeTarget
{
    /// <summary>
    /// Returns an user-friendly identifier of this make target.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Returns an enumerable of make target files in linking order.
    /// </summary>
    IEnumerable<IAsmFile> GetFiles();

    /// <summary>
    /// Returns a make target file of given <paramref name="name"/>.
    /// </summary>
    /// <param name="name">The name of the make target file.</param>
    /// <returns>The make target ASM file or null if no such file exists.</returns>
    IAsmFile? GetFile(string name);
}
