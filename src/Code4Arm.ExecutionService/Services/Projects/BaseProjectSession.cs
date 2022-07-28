// BaseProjectSession.cs
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

using Code4Arm.ExecutionCore.Assembling;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.FunctionSimulators;
using Code4Arm.ExecutionCore.Execution.FunctionSimulators.Stdio;
using Code4Arm.ExecutionCore.Files.Abstractions;

namespace Code4Arm.ExecutionService.Services.Projects;

public abstract class BaseProjectSession : IProjectSession
{
    private bool _disposed;
    protected readonly Assembler Assembler;
    private MakeResult? _lastResult;

    public abstract string Name { get; }
    public abstract IEnumerable<IAsmFile> GetFiles();
    public abstract IAsmFile? GetFile(string name);
    public abstract bool Dirty { get; }

    public BaseProjectSession(AssemblerOptions assemblerOptions, LinkerOptions linkerOptions,
        IFunctionSimulator[] simulators, ILoggerFactory loggerFactory)
    {
        Assembler = new Assembler(assemblerOptions, linkerOptions, loggerFactory);
        Assembler.UseFunctionSimulators(simulators);
    }

    public void UseAssemblerOptions(AssemblerOptions options)
    {
        Assembler.AssemblerOptions = options;
        _lastResult = null;
    }

    public void UseLinkerOptions(LinkerOptions options)
    {
        Assembler.LinkerOptions = options;
        _lastResult = null;
    }

    public virtual async Task<MakeResult> Build(bool rebuild)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(BaseProjectSession));

        if (!rebuild && _lastResult != null && !Dirty)
            return _lastResult.Value;

        var result = await Assembler.MakeProject(this);
        _lastResult = result;

        return result;
    }

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            Assembler.Dispose();

            if (_lastResult.HasValue)
            {
                _lastResult.Value.Executable?.Dispose();
                foreach (var asmObject in _lastResult.Value.ValidObjects)
                {
                    asmObject.Dispose();
                }
            }
        }

        _disposed = true;
    }

    ~BaseProjectSession()
    {
        this.Dispose(false);
    }
}
