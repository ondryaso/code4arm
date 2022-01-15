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

    private const int MemorySize = 4096 * 1;

    internal PoCExecutionContext(PoCProject project)
    {
        this.Project = project;
        Unicorn = new Unicorn(Common.UC_ARCH_ARM,
            Common.UC_MODE_ARM);
        _state = new PoCInternalExecutionState(this);
        _memory = new PoCExecutionMemory(this);

        this.Input = new MemoryStream();
        this.Output = new MemoryStream();

        var src = project.PoCSource;

        Unicorn.MemMap(0, MemorySize, Common.UC_PROT_ALL);
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

    public void RunToBreakpoint()
    {
        if (this.Ended ||
            _currentAddress >= this.Project.PoCSource.AssembledCodeLength * 4)
        {
            return;
        }

        var nextBreakpoint = _state.Breakpoints.FirstOrDefault(s => s.Line >= _currentLine);
        var nextAddress = this.Project.PoCSource.AssembledCodeLength * 4;

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

        if (nextAddress >= this.Project.PoCSource.AssembledCodeLength * 4)
        {
            this.Ended = true;
            this.ExecutionState = ExecutionState.Ended;
        }
    }

    public void Step()
    {
        if (this.Ended ||
            _currentAddress >= this.Project.PoCSource.AssembledCodeLength * 4)
        {
            return;
        }

        Unicorn.EmuStart(_currentAddress, _currentAddress + 4, 0, 0);
        this.ExecutionState = ExecutionState.Breakpoint;
        this.CurrentBreakpoint = new PoCBreakpoint()
            { Line = this.Project.PoCSource.AddressToLine((uint)_currentAddress) };
        _currentAddress += 4;

        if (_currentAddress >= this.Project.PoCSource.AssembledCodeLength * 4)
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

        Unicorn.MemUnmap(0, MemorySize);
        Unicorn.Dispose();
    }
}
