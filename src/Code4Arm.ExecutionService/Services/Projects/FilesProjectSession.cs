// FilesProjectSession.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Code4Arm.ExecutionService.Files;

namespace Code4Arm.ExecutionService.Services.Projects;

public class FilesProjectSession : BaseProjectSession
{
    public record File(string ClientPath, string FilesystemPath, int? Version);
    
    private readonly Dictionary<string, LocalAsmFile> _files = new();
    private readonly object _loadingLocker = new();
    private bool _reloaded = false;

    public FilesProjectSession(string? name,
        AssemblerOptions assemblerOptions, LinkerOptions linkerOptions,
        IFunctionSimulator[] simulators, ILoggerFactory loggerFactory)
        : base(assemblerOptions, linkerOptions, simulators, loggerFactory)
    {
        Name = name ?? Guid.NewGuid().ToString();
    }

    public void UseFiles(ICollection<File> files)
    {
        lock (_loadingLocker)
        {
            foreach (var file in files)
            {
                if (_files.ContainsKey(file.ClientPath))
                    continue;

                var asmFile = new LocalAsmFile(file.FilesystemPath, file.ClientPath, null, this) { LastBuiltVersion = -1 };
                if (file.Version.HasValue)
                    asmFile.Version = file.Version.Value;
                
                _files.Add(file.ClientPath, asmFile);
                _reloaded = true;
            }

            var sessionFiles = _files.Keys.ToList();
            foreach (var sessionFile in sessionFiles)
            {
                if (!files.Any(f => f.ClientPath == sessionFile))
                {
                    _files.Remove(sessionFile);
                    _reloaded = true;
                }
            }
        }
    }

    public override string Name { get; }

    public override IEnumerable<IAsmFile> GetFiles()
    {
        IEnumerable<IAsmFile> files;
        lock (_loadingLocker)
        {
            files = _files.Values.ToArray();
        }

        return files;
    }

    public override IAsmFile? GetFile(string name)
    {
        lock (_loadingLocker)
        {
            return _files.TryGetValue(name, out var f) ? f : null;
        }
    }

    public override async Task<MakeResult> Build(bool rebuild)
    {
        var result = await base.Build(rebuild);
        
        lock (_loadingLocker)
        {
            _reloaded = false;
            
            foreach (var file in _files.Values)
            {
                file.LastBuiltVersion = file.Version;
            }
        }
        
        return result;
    }

    public override bool Dirty
    {
        get
        {
            lock (_loadingLocker)
            {
                return _files.Values.Any(f => f.LastBuiltVersion != f.Version) || _reloaded;
            }
        }
    }
}
