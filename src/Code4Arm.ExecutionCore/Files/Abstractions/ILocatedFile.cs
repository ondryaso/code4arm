// ILocatedFile.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Files.Abstractions;

/// <summary>
/// Represents a 'disposable filesystem path'. When acquiring an instance of <see cref="ILocatedFile"/>, the owner can
/// presume that a <see cref="IAsmFile"/> representation is saved in the filesystem, at the path given by
/// <see cref="FileSystemPath"/>.
/// When finished working with it, the <see cref="ILocatedFile"/> instance should be disposed which provides way of
/// cleaning
/// up the file if it was only temporary.
/// </summary>
public interface ILocatedFile : IDisposable
{
    /// <summary>
    /// The path of the filesystem representation of <see cref="File"/>.
    /// </summary>
    string FileSystemPath { get; }

    /// <summary>
    /// The version of <see cref="File"/> saved in the filesystem. This may not correspond with the value of the
    /// <see cref="IAsmFile.Version"/> property of <see cref="File"/>, in which case the caller may dispose this
    /// <see cref="ILocatedFile"/> and request a new one.
    /// </summary>
    int Version { get; }

    /// <summary>
    /// The <see cref="IAsmFile"/> that is the source of this representation.
    /// </summary>
    IAsmFile File { get; }
}
