// LocalAsmFile.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

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
