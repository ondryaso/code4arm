// PoCExecutionRegisters.cs
// Author: Ondřej Ondryáš

using System.Collections;
using Armulator.ExecutionService.Execution.Abstractions;
using UnicornManaged;
using UnicornManaged.Const;

namespace Armulator.ExecutionService.Execution.ProofOfConcept;

public class PoCExecutionRegisters : IRegisterFile<int>
{
    private readonly Unicorn _unicorn;

    private int MapRegisterNumberToUnicornConstant(int number)
    {
        return number switch
        {
            > 0 and <= 12 => Arm.UC_ARM_REG_R0 + number,
            13 => Arm.UC_ARM_REG_SP,
            14 => Arm.UC_ARM_REG_LR,
            15 => Arm.UC_ARM_REG_PC,
            16 => Arm.UC_ARM_REG_CPSR,
            _ => throw new ArgumentException("Invalid register number.", nameof(number))
        };
    }

    public IEnumerator<int> GetEnumerator()
    {
        // TODO: Enumerate through Unicorn registers
        throw new NotImplementedException();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return this.GetEnumerator();
    }

    internal PoCExecutionRegisters(Unicorn unicorn)
    {
        _unicorn = unicorn;
    }

    public int Count => 17;

    public int this[int index]
    {
        get => (int)_unicorn.RegRead(this.MapRegisterNumberToUnicornConstant(index));

        set => _unicorn.RegWrite(this.MapRegisterNumberToUnicornConstant(index), value);
    }
}
