// UnicornHookRegistration.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.Unicorn.Abstractions;

public readonly struct UnicornHookRegistration : IEquatable<UnicornHookRegistration>
{
    internal nuint NativeHookId { get; init; }
    internal int ManagedHookId { get; init; }
    public IUnicorn Unicorn { get; internal init; }
    public Delegate Callback { get; internal init; }
    public ulong StartAddress { get; internal init; }
    public ulong EndAddress { get; internal init; }
    public int HookType { get; internal init; }

    public void RemoveHook()
    {
        Unicorn.RemoveHook(this);
    }

    public bool Equals(UnicornHookRegistration other) =>
        ReferenceEquals(Unicorn, other.Unicorn)
        && NativeHookId.Equals(other.NativeHookId)
        && ManagedHookId == other.ManagedHookId;

    public override bool Equals(object? obj) => obj is UnicornHookRegistration other && this.Equals(other);

    public override int GetHashCode() => HashCode.Combine(Unicorn, NativeHookId, ManagedHookId);

    public static bool operator ==(UnicornHookRegistration left, UnicornHookRegistration right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(UnicornHookRegistration left, UnicornHookRegistration right)
    {
        return !(left == right);
    }
}
