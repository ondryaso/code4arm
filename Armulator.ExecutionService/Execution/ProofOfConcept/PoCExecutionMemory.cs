// PoCExecutionMemory.cs
// Author: Ondřej Ondryáš

using System.Buffers;
using Armulator.ExecutionService.Execution.Abstractions;
using UnicornManaged;

namespace Armulator.ExecutionService.Execution.ProofOfConcept;

internal class PoCExecutionMemory : IExecutionMemory
{
    private readonly PoCExecutionContext _context;
    private readonly Unicorn _unicorn;
    private PoCProject Project => _context.Project;
    private PoCSource Source => this.Project.PoCSource;

    internal PoCExecutionMemory(PoCExecutionContext context)
    {
        _context = context;
        _unicorn = context.Unicorn;
    }

    public int TotalSize => throw new NotImplementedException();

    public ReadOnlySpan<byte> this[int position, int length]
    {
        get
        {
            // TODO: find a way not to allocate an array every time the internal memory is accessed
            var target = new byte[length];
            _unicorn.MemRead(position, target);
            return target;
        }

        set => _unicorn.MemWrite(position, value.Slice(0, length).ToArray());
    }

    public ReadOnlySpan<byte> this[int position]
    {
        set => _unicorn.MemWrite(position, value.ToArray());
    }

    public IEnumerable<IMemoryRegion> Regions => throw new NotImplementedException();
}
