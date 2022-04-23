// ContainerBase.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using System.Collections;

namespace Code4Arm.ExecutionCore.Protocol.Models;

public abstract class ContainerBase<T> : IEnumerable<T>, IEquatable<ContainerBase<T>>
{
    private readonly IEnumerable<T> _items;

    public ContainerBase(IEnumerable<T> items)
    {
        _items = items.ToArray();
    }

    public IEnumerator<T> GetEnumerator() => _items.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => this.GetEnumerator();

    public bool Equals(ContainerBase<T>? other) =>
        other is not null &&
        _items.SequenceEqual(other._items);

    public override bool Equals(object? obj) => this.Equals(obj as ContainerBase<T>);

    public override int GetHashCode() => -566117206 + EqualityComparer<IEnumerable<T>>.Default.GetHashCode(_items);

    public static bool operator ==(ContainerBase<T> base1, ContainerBase<T> base2) =>
        EqualityComparer<ContainerBase<T>>.Default.Equals(base1, base2);

    public static bool operator !=(ContainerBase<T> base1, ContainerBase<T> base2) => !(base1 == base2);
}
