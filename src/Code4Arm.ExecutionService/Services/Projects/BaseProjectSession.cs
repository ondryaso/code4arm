// BaseProjectSession.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling;
using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Microsoft.Extensions.Options;

namespace Code4Arm.ExecutionService.Services.Projects;

public abstract class BaseProjectSession : IProjectSession
{
    private bool _disposed;
    protected Assembler? Assembler;
    private MakeResult? _lastResult;

    private readonly IDisposable _assemblerOptionsChangeHandler;
    private readonly IDisposable _linkerOptionsChangeHandler;

    public abstract string Name { get; }
    public abstract IEnumerable<IAsmFile> GetFiles();
    public abstract IAsmFile? GetFile(string name);
    public abstract bool Dirty { get; }

    public BaseProjectSession(IOptionsMonitor<AssemblerOptions> assemblerOptions,
        IOptionsMonitor<LinkerOptions> linkerOptions, ILoggerFactory loggerFactory)
    {
        Assembler = new Assembler(assemblerOptions.CurrentValue, linkerOptions.CurrentValue, loggerFactory);
        _assemblerOptionsChangeHandler = assemblerOptions.OnChange(opt => Assembler.AssemblerOptions = opt);
        _linkerOptionsChangeHandler = linkerOptions.OnChange(opt => Assembler.LinkerOptions = opt);
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

    public async Task Use(IExecutionEngine execution)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(BaseProjectSession));

        if (_lastResult is { State: MakeResultState.Successful })
        {
            var exe = _lastResult.Value.Executable!;
            if (exe != execution.ExecutableInfo && execution.State is ExecutionState.Ready or ExecutionState.Finished
                    or ExecutionState.TerminatedException or ExecutionState.TerminatedManually)
                await execution.LoadExecutable(exe).ConfigureAwait(false);
        }
    }

    public Task<IDebugProtocolSourceLocator> GetSourceLocator()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(BaseProjectSession));

        if (_lastResult is not { Executable: { } })
            throw new InvalidOperationException();

        return Task.FromResult<IDebugProtocolSourceLocator>(_lastResult.Value.Executable!);
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
            _assemblerOptionsChangeHandler.Dispose();
            _linkerOptionsChangeHandler.Dispose();

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
