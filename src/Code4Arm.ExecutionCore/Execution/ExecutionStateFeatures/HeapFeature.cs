// HeapFeature.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;

namespace Code4Arm.ExecutionCore.Execution.ExecutionStateFeatures;

public class HeapFeature : IExecutionStateFeature
{
    private struct AllocatedChunk
    {
        public uint Start;
        public uint Size;
        public uint End;

        public AllocatedChunk(uint start, uint size)
        {
            Start = start;
            Size = size;
            End = start + size;
        }
    }

    private readonly ExecutionEngine _engine;
    private bool _mapped;
    private MemorySegment? _heapSegment;
    private List<AllocatedChunk> _chunks = new();

    public HeapFeature(ExecutionEngine engine)
    {
        _engine = engine;
    }

    public void InitMemory(List<MemorySegment> segments)
    {
        // _segments = segments;
        foreach (var existing in segments.Where(s => s.IsHeap))
        {
            _engine.Engine.MemUnmap(existing.StartAddress, existing.Size);
        }

        segments.RemoveAll(s => s.IsHeap);

        _heapSegment = new MemorySegment(0xfc000000, 4 * 1024 * 1024)
        {
            Permissions = MemorySegmentPermissions.Read | MemorySegmentPermissions.Write,
            IsHeap = true
        };
        
        segments.Add(_heapSegment);
        _mapped = false;

        _chunks.Clear();
    }

    public void ClearAllocatedMemory()
    {
        _chunks.Clear();
    }

    public uint? Allocate(uint size, bool zero)
    {
        if (_heapSegment == null)
            return null;

        if (!_mapped)
        {
            Task.Run(async () => await _engine.LogSegmentMapped(_heapSegment));

            _engine.Engine.MemMap(_heapSegment.StartAddress, _heapSegment.Size, _heapSegment.Permissions.ToUnicorn());
            
            _mapped = true;
        }

        var address = 0u;
        if (_chunks.Count == 0)
        {
            if (size > _heapSegment.Size)
                return null;

            _chunks.Add(new AllocatedChunk(0u, size));
        }
        else
        {
            if (_chunks[0].Start >= size)
            {
                _chunks.Insert(0, new AllocatedChunk(0, size));
            }
            else
            {
                var found = false;
                var insertIndex = 0;

                for (var i = 0; i < _chunks.Count - 1 && !found; i++)
                {
                    insertIndex++;
                    address = _chunks[i].End;
                    if (address + size < _chunks[i + 1].Start)
                        found = true;
                }

                if (!found)
                {
                    insertIndex++;
                    address = _chunks[^1].End;
                    if (address + size < _heapSegment.Size)
                        found = true;
                }

                if (!found)
                    return null;

                _chunks.Insert(insertIndex, new AllocatedChunk(address, size));
            }
        }

        if (zero)
            _engine.ClearMemory(_heapSegment.StartAddress + address, size);

        return _heapSegment.StartAddress + address;
    }

    public bool Free(uint pointer)
    {
        if (_heapSegment == null)
            return false;

        var relativeAddress = pointer - _heapSegment.StartAddress;
        var index = _chunks.FindIndex(c => c.Start == relativeAddress);

        if (index == -1)
            return false;

        _chunks.RemoveAt(index);

        return true;
    }

    public uint? Reallocate(uint pointer, uint newSize)
    {
        if (_heapSegment == null)
            return null;

        if (pointer == 0)
            return this.Allocate(newSize, false);

        var relativeAddress = pointer - _heapSegment.StartAddress;
        var index = _chunks.FindIndex(c => c.Start == relativeAddress);

        if (index == -1)
            return null;

        var nextIndex = index + 1;
        var chunk = _chunks[index];

        if (chunk.Size > newSize)
        {
            // Contracting
            chunk = new AllocatedChunk(chunk.Start, newSize);
            _chunks.RemoveAt(index);
            _chunks.Insert(index, chunk);

            return _heapSegment.StartAddress + chunk.Start;
        }

        if (_chunks.Count > nextIndex)
        {
            var nextChunk = _chunks[index + 1];
            if (nextChunk.Start > chunk.Start + newSize)
            {
                chunk = new AllocatedChunk(chunk.Start, newSize);
                _chunks.RemoveAt(index);
                _chunks.Insert(index, chunk);

                return _heapSegment.StartAddress + chunk.Start;
            }
        }
        else if (_chunks.Count == nextIndex)
        {
            if (chunk.Start + newSize < _heapSegment.Size)
            {
                chunk = new AllocatedChunk(chunk.Start, newSize);
                _chunks.RemoveAt(index);
                _chunks.Insert(index, chunk);

                return _heapSegment.StartAddress + chunk.Start;
            }
        }

        var newSpace = this.Allocate(newSize, false);

        if (newSpace == null)
            return null;

        var data = _engine.ArrayPool.Rent((int)chunk.Size);
        _engine.Engine.MemRead(_heapSegment.StartAddress, data, chunk.Size);
        _engine.Engine.MemWrite(newSpace.Value, data, chunk.Size);

        _chunks.RemoveAt(index);

        return newSpace;
    }
}
