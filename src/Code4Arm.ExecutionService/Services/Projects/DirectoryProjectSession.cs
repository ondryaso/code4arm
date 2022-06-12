// DirectoryProjectSession.cs
// Author: Ondřej Ondryáš

using System.Collections.Concurrent;
using Code4Arm.ExecutionCore.Assembling;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Code4Arm.ExecutionService.Files;
using MediatR;
using Microsoft.Extensions.Options;

namespace Code4Arm.ExecutionService.Services.Projects;

public class DirectoryProjectSession : BaseProjectSession
{
    private readonly Dictionary<string, LocalAsmFile> _files = new();

    private readonly ConcurrentBag<string>? _filesToAdd;
    private readonly ConcurrentBag<string>? _filesToRemove;

    private readonly object _loadingLocker = new();
    private readonly string _rootDirectoryPath;

    private bool _disposed;

    private bool _dirty;

    private readonly FileSystemWatcher _dirWatcher;
    private bool _needsReload, _needsFullReload;

    public override string Name { get; }
    public override bool Dirty => _dirty;

    public string DirectoryPath => _rootDirectoryPath;

    public DirectoryProjectSession(string rootDirectoryPath,
        AssemblerOptions assemblerOptions, LinkerOptions linkerOptions, IFunctionSimulator[] simulators,
        ILoggerFactory loggerFactory)
        : base(assemblerOptions, linkerOptions, simulators, loggerFactory)
    {
        _rootDirectoryPath = rootDirectoryPath;

        Name = Path.GetFileName(rootDirectoryPath);

        _filesToAdd = new ConcurrentBag<string>();
        _filesToRemove = new ConcurrentBag<string>();

        _dirWatcher = new FileSystemWatcher(rootDirectoryPath)
        {
            IncludeSubdirectories = true,
            Filters = { "*.s", "*.S" },
            NotifyFilter = NotifyFilters.DirectoryName | NotifyFilters.FileName | NotifyFilters.CreationTime |
                NotifyFilters.LastWrite
        };

        _dirWatcher.Created += (_, e) =>
        {
            _dirty = true;
            _needsReload = true;

            _filesToAdd.Add(e.FullPath);
        };

        _dirWatcher.Changed += (_, _) => _dirty = true;

        _dirWatcher.Renamed += (_, _) =>
        {
            _dirty = true;
            _needsReload = true;
            _needsFullReload = true;
        };

        _dirWatcher.Deleted += (_, e) =>
        {
            _dirty = true;
            _needsReload = true;

            _filesToRemove.Add(e.FullPath);
        };

        _needsReload = _needsFullReload = true;
        this.LoadFiles(); // Enables the watcher
    }

    public override IEnumerable<IAsmFile> GetFiles()
    {
        if (_needsReload)
            this.LoadFiles();

        lock (_loadingLocker)
        {
            var copy = new LocalAsmFile[_files.Count];
            _files.Values.CopyTo(copy, 0);

            return copy;
        }
    }

    public override IAsmFile? GetFile(string name)
    {
        if (_needsReload)
            this.LoadFiles();

        lock (_loadingLocker)
        {
            return _files.TryGetValue(name, out var val) ? val : null;
        }
    }

    private void LoadFiles()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(BaseProjectSession));

        _needsReload = false;
        _dirty = false;

        if (_needsFullReload)
        {
            // This could, in theory, lead to some files getting missed, but it's highly improbable
            _dirWatcher!.EnableRaisingEvents = false;
            _filesToAdd?.Clear();
            _filesToRemove?.Clear();
            var allFiles = Directory.GetFiles(_rootDirectoryPath, "*.s", SearchOption.AllDirectories);
            _dirWatcher!.EnableRaisingEvents = true;

            lock (_loadingLocker)
            {
                _files.Clear();

                foreach (var path in allFiles)
                {
                    var name = Path.GetRelativePath(_rootDirectoryPath, path);
                    _files.Add(name, new LocalAsmFile(path, name, this) { LastBuiltVersion = -1 });
                }
            }

            _needsFullReload = false;
            _dirty = false;
            _needsReload = false;

            return;
        }

        lock (_loadingLocker)
        {
            if (_filesToAdd != null)
                while (_filesToAdd.TryTake(out var toAdd))
                {
                    var name = Path.GetRelativePath(_rootDirectoryPath, toAdd);
                    _files.Add(name, new LocalAsmFile(toAdd, name, this));
                }

            if (_filesToRemove != null)
                while (_filesToRemove.TryTake(out var toAdd))
                {
                    var name = Path.GetRelativePath(_rootDirectoryPath, toAdd);
                    _files.Remove(name);
                }
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            _dirWatcher.EnableRaisingEvents = false;
            _dirWatcher.Dispose();
        }

        _disposed = true;

        base.Dispose(disposing);
    }

    ~DirectoryProjectSession()
    {
        this.Dispose(false);
    }
}
