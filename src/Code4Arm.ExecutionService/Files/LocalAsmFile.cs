// LocalAsmFile.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Files.Abstractions;
using Microsoft.Win32.SafeHandles;

namespace Code4Arm.ExecutionService.Files;

public class LocalAsmFile : IAsmFile, IEquatable<LocalAsmFile>
{
    private class LocalLocatedFile : ILocatedFile, IEquatable<LocalLocatedFile>
    {
        internal bool Disposed { get; private set; }
        private readonly SafeFileHandle _handle;

        public LocalLocatedFile(string fileSystemPath, int version, IAsmFile file)
        {
            FileSystemPath = fileSystemPath;
            Version = version;
            File = file;

            _handle = System.IO.File.OpenHandle(fileSystemPath, FileMode.Open, FileAccess.Read,
                FileShare.Read, FileOptions.None);
        }

        public void Dispose()
        {
            if (Disposed)
                return;

            _handle.Dispose();
            Disposed = true;
        }

        public string FileSystemPath { get; }
        public int Version { get; }
        public IAsmFile File { get; }
        public bool Equals(LocalLocatedFile? other) => throw new NotImplementedException();
    }

    private readonly string _fsPath;
    private LocalLocatedFile? _lastLocated;
    private int? _forcedVersion;

    internal LocalAsmFile(string fsPath, string? name = null, IAsmMakeTarget? project = null)
    {
        _fsPath = fsPath;

        Name = name ?? Path.GetFileName(_fsPath);
        ClientPath = _fsPath;
        Project = project;
    }

    internal LocalAsmFile(string fsPath, string clientPath, string? name = null, IAsmMakeTarget? project = null)
    {
        _fsPath = fsPath;
        Name = name ?? Path.GetFileName(clientPath);
        ClientPath = clientPath;
        Project = project;
    }

    public string Name { get; }
    public string FileSystemPath => _fsPath;

    public int Version
    {
        get => _forcedVersion ?? (int)(File.GetLastWriteTime(_fsPath).Ticks % int.MaxValue);
        set => _forcedVersion = value;
    }

    public string ClientPath { get; }
    public IAsmMakeTarget? Project { get; }
    public int LastBuiltVersion { get; set; }

    public ValueTask<ILocatedFile> LocateAsync()
    {
        var currentVersion = Version;

        if (_lastLocated == null || currentVersion != _lastLocated.Version || _lastLocated.Disposed)
            _lastLocated = new LocalLocatedFile(_fsPath, currentVersion, this);

        return new ValueTask<ILocatedFile>(_lastLocated);
    }

    public bool Equals(IAsmFile? other) => other is LocalAsmFile file && this.Equals(file);

    public bool Equals(LocalAsmFile? other) => other != null && _fsPath == other._fsPath
        && LastBuiltVersion == other.LastBuiltVersion;

    public override bool Equals(object? obj) =>
        ReferenceEquals(obj, this) || obj is LocalAsmFile file && this.Equals(file);

    public override int GetHashCode() => _fsPath.GetHashCode();
}
