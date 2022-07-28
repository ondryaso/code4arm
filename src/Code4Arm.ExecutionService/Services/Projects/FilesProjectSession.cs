// FilesProjectSession.cs
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
