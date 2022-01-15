// PoCExecutionContext.cs
// Author: Ondřej Ondryáš

using Armulator.ExecutionService.Execution.Abstractions;
using UnicornManaged;
using UnicornManaged.Const;

namespace Armulator.ExecutionService.Execution.ProofOfConcept;

public class PoCExecutionContext : IExecutionContext
{
    private readonly PoCInternalExecutionState _state;
    private readonly PoCExecutionMemory _memory;

    internal readonly Unicorn Unicorn;
    internal PoCProject Project { get; }

    internal PoCExecutionContext(PoCProject project)
    {
        this.Project = project;
        Unicorn = new Unicorn(Common.UC_ARCH_ARM,
            Common.UC_MODE_ARM | Common.UC_MODE_V8 | Common.UC_MODE_LITTLE_ENDIAN);
        _state = new PoCInternalExecutionState(this);
        _memory = new PoCExecutionMemory(this);

        this.Input = new MemoryStream();
        this.Output = new MemoryStream();

        var src = project.PoCSource;

        Unicorn.MemMap(0, src.AssembledCodeLength, Common.UC_PROT_READ | Common.UC_PROT_EXEC);
        Unicorn.MemWrite(0, src.AssembledCode!.Value.ToArray());
        Unicorn.AddCodeHook(this.CodeHook, 0, src.AssembledCodeLength);

        this.ExecutionState = ExecutionState.Ready;
        _currentAddress = 0;
    }

    public IProjectState InternalState => _state;

    public ExecutionState ExecutionState { get; private set; }

    public IExecutionMemory Memory => _memory;

    public bool Ended { get; private set; }

    public IBreakpoint? CurrentBreakpoint { get; private set; }

    public Stream Input { get; }
    public Stream Output { get; }

    private int _currentAddress;
    private int _currentLine;
    //private int _currentInstruction;

    private void CodeHook(Unicorn unicorn, ulong address, uint size, object userData)
    {
        _currentAddress = (int)address;
        _currentLine = this.Project.PoCSource.AddressToLine((uint)_currentAddress);
        //_currentInstruction = this.Project.PoCSource.LineToInstruction(_currentLine);
    }

    public void Run()
    {
        if (this.Ended ||
            _currentAddress >= this.Project.PoCSource.AssembledCodeLength)
        {
            return;
        }

        var nextBreakpoint = _state.Breakpoints.FirstOrDefault(s => s.Line >= _currentLine);
        var nextAddress = this.Project.PoCSource.AssembledCodeLength;

        if (nextBreakpoint != null)
        {
            nextAddress = this.Project.PoCSource.LineToAddress(nextBreakpoint.Line);
        }

        this.ExecutionState = ExecutionState.Running;
        Unicorn.EmuStart(_currentAddress, nextAddress, 0, 0);

        if (nextBreakpoint != null)
        {
            this.ExecutionState = ExecutionState.Breakpoint;
            this.CurrentBreakpoint = nextBreakpoint;
        }

        _currentAddress = nextAddress;

        if (nextAddress >= this.Project.PoCSource.AssembledCodeLength)
        {
            this.Ended = true;
            this.ExecutionState = ExecutionState.Ended;
        }
    }

    public void Halt()
    {
        this.Ended = true;
        this.ExecutionState = ExecutionState.Ended;
    }

    public void Dispose()
    {
        if (!this.Ended)
        {
            this.Halt();
        }

        Unicorn.MemUnmap(0, this.Project.PoCSource.AssembledCodeLength);
        Unicorn.Dispose();
    }
}
