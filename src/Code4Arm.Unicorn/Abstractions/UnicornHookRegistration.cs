// UnicornHookRegistration.cs
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
