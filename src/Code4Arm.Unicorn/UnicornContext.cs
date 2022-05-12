// UnicornContext.cs
// Author: Ondřej Ondryáš

using Code4Arm.Unicorn.Abstractions;

namespace Code4Arm.Unicorn;

internal sealed class UnicornContext : IUnicornContext
{
    internal bool Disposed;

    public Unicorn Unicorn { get; }
    public UIntPtr Context { get; }

    public UnicornContext(Unicorn unicorn, UIntPtr contextPtr)
    {
        Unicorn = unicorn;
        Context = contextPtr;
    }

    public void RegWrite<T>(int registerId, T value) where T : unmanaged
    {
        this.EnsureNotDisposed();
        int result;

        unsafe
        {
            result = Native.uc_context_reg_write(Context, registerId, &value);
        }

        Unicorn.CheckResult(result);
    }

    public T RegRead<T>(int registerId) where T : unmanaged
    {
        this.EnsureNotDisposed();
        int result;
        T value;

        unsafe
        {
            result = Native.uc_context_reg_read(Context, registerId, &value);
        }

        Unicorn.CheckResult(result);

        return value;
    }

    public unsafe void RegWrite(int registerId, ReadOnlySpan<byte> bytes)
    {
        this.EnsureNotDisposed();
        int result;

        fixed (byte* pinned = bytes)
        {
            result = Native.uc_reg_write(Context, registerId, pinned);
        }

        Unicorn.CheckResult(result);
    }

    public unsafe void RegRead(int registerId, Span<byte> target)
    {
        this.EnsureNotDisposed();
        int result;

        fixed (byte* pinned = target)
        {
            result = Native.uc_reg_read(Context, registerId, pinned);
        }

        Unicorn.CheckResult(result);
    }

    public unsafe void RegBatchWrite<T>(int[] registerIds, IEnumerable<T> values) where T : unmanaged
    {
        this.EnsureNotDisposed();

        var valuesArray = stackalloc T[registerIds.Length];
        var pointersToValues = stackalloc void*[registerIds.Length];

        var i = 0;
        foreach (var value in values)
        {
            valuesArray[i] = value;
            pointersToValues[i] = &valuesArray[i++];

            if (i == registerIds.Length)
                break;
        }

        if (i != registerIds.Length)
            throw new ArgumentException($"Expected {registerIds.Length} values, got {i}.", nameof(values));

        int result;
        fixed (int* regIdsPtr = registerIds)
        {
            result = Native.uc_context_reg_write_batch(Context, regIdsPtr, pointersToValues, registerIds.Length);
        }

        Unicorn.CheckResult(result);
    }

    public unsafe void RegBatchWrite<T>(int[] registerIds, ReadOnlySpan<T> values) where T : unmanaged
    {
        this.EnsureNotDisposed();

        if (values.Length != registerIds.Length)
            throw new ArgumentException($"Expected {registerIds.Length} values, got {values.Length}.", nameof(values));

        var pointersToValues = stackalloc void*[registerIds.Length];
        int result;

        fixed (T* valuesPinned = values)
        {
            for (var i = 0; i < registerIds.Length; i++)
            {
                pointersToValues[i] = &valuesPinned[i];
            }

            fixed (int* regIdsPtr = registerIds)
            {
                result = Native.uc_context_reg_write_batch(Context, regIdsPtr, pointersToValues,
                    registerIds.Length);
            }
        }

        Unicorn.CheckResult(result);
    }

    public unsafe void RegBatchRead<T>(int[] registerIds, Span<T> target) where T : unmanaged
    {
        this.EnsureNotDisposed();

        var pointersToValues = stackalloc void*[registerIds.Length];
        int result;

        fixed (T* targetPinned = target)
        {
            for (var i = 0; i < target.Length; i++)
            {
                pointersToValues[i] = &targetPinned[i];
            }

            fixed (int* regIdsPinned = registerIds)
            {
                result = Native.uc_context_reg_read_batch(Context, regIdsPinned, pointersToValues,
                    registerIds.Length);
            }
        }

        Unicorn.CheckResult(result);
    }

    public unsafe T[] RegBatchRead<T>(int[] registerIds) where T : unmanaged
    {
        this.EnsureNotDisposed();

        var pointersToValues = stackalloc void*[registerIds.Length];
        var retArray = new T[registerIds.Length];
        int result;

        fixed (T* targetPinned = retArray)
        {
            for (var i = 0; i < registerIds.Length; i++)
            {
                pointersToValues[i] = &targetPinned[i];
            }

            fixed (int* regIdsPinned = registerIds)
            {
                result = Native.uc_context_reg_read_batch(Context, regIdsPinned, pointersToValues,
                    registerIds.Length);
            }
        }

        Unicorn.CheckResult(result);

        return retArray;
    }

    private void EnsureNotDisposed()
    {
        Unicorn.EnsureEngine();

        if (Disposed)
            throw new ObjectDisposedException(nameof(UnicornContext),
                "This Unicorn context has already been disposed.");
    }

    #region Disposal

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (Disposed)
            return;

        if (disposing)
        {
            // Dispose managed objects
            // Intentionally left blank
        }

        _ = Native.uc_context_free(Context);
        // Best effort: If closing failed, we can't really do anything about it

        Disposed = true;
    }

    ~UnicornContext()
    {
        this.Dispose(false);
    }

    #endregion
}
