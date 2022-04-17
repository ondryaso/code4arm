// IAsmProject.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Files.Abstractions;

/// <summary>
/// An abstraction over a set of assembly source files that are assembled and linked together.
/// </summary>
public interface IAsmProject
{
    /// <summary>
    /// Returns an user-friendly identifier of this project.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Returns an enumerable of project files in linking order.
    /// </summary>
    IEnumerable<IAsmFile> GetFiles();

    /// <summary>
    /// Returns a project file of given <paramref name="name"/>.
    /// </summary>
    /// <param name="name">The name of the project file.</param>
    /// <returns>The project ASM file or null if no such file exists.</returns>
    IAsmFile? GetFile(string name);
}
