// IAsmFile.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Files.Abstractions;

/// <summary>
/// An abstraction over an assembly source file. It provides a way to ensure the source file is stored in the filesystem
/// so that it can be processed by external tools.
/// </summary>
public interface IAsmFile
{
    /// <summary>
    /// The workspace-relative name of this file.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// The current version of this file.
    /// </summary>
    /// <remarks>
    /// The <see cref="Version"/> property is used to detect changes. This is used to cache previously assembled object
    /// files if their sources have not changed.
    /// </remarks>
    int Version { get; }

    /// <summary>
    /// The project this file belongs to.
    /// </summary>
    IAsmProject? Project { get; }

    /// <summary>
    /// Asynchronously ensures that this file exists in the filesystem and returns a disposable container over its location.
    /// </summary>
    /// <remarks>
    /// A call to <see cref="LocateAsync"/> may simply return a filesystem file or it may, e.g., save a file from
    /// a database to a temporary location. When the caller stops using this file, it should dispose the corresponding
    /// <see cref="ILocatedFile"/>, which would delete the temporary file.
    /// </remarks>
    /// <returns>A disposable filesystem path pointing to this file.</returns>
    Task<ILocatedFile> LocateAsync();
}
