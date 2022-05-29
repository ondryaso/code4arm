// BaseProjectSession.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling;
using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.FunctionSimulators;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Microsoft.Extensions.Options;

namespace Code4Arm.ExecutionService.Services.Projects;

public abstract class BaseProjectSession : IProjectSession
{
    private bool _disposed;
    protected Assembler Assembler;
    private MakeResult? _lastResult;

    public abstract string Name { get; }
    public abstract IEnumerable<IAsmFile> GetFiles();
    public abstract IAsmFile? GetFile(string name);
    public abstract bool Dirty { get; }

    public BaseProjectSession(AssemblerOptions assemblerOptions, LinkerOptions linkerOptions,
        ILoggerFactory loggerFactory)
    {
        Assembler = new Assembler(assemblerOptions, linkerOptions, loggerFactory);
        Assembler.UseFunctionSimulators(new IFunctionSimulator[] {new Printf()}); // TODO: get from DI?
    }

    public void UseAssemblerOptions(AssemblerOptions options)
    {
        Assembler.AssemblerOptions = options;
    }

    public void UseLinkerOptions(LinkerOptions options)
    {
        Assembler.LinkerOptions = options;
    }

    public async Task<MakeResult> Build(bool rebuild)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(BaseProjectSession));

        if (!rebuild && _lastResult != null && !Dirty)
            return _lastResult.Value;

        if (Assembler == null)
            throw new InvalidOperationException("The assembler is not initialized.");

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
            Assembler?.Dispose();

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
