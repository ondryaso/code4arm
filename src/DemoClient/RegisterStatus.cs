// RegisterStatus.cs
// Author: Ondřej Ondryáš

namespace DemoClient;

public class RegisterStatus
{
    public int R0 { get; set; }
    public int R1 { get; set; }
    public int R2 { get; set; }
    public int R3 { get; set; }
    public int R4 { get; set; }
    public int R5 { get; set; }
    public int R6 { get; set; }
    public int R7 { get; set; }
    public int R8 { get; set; }
    public int R9 { get; set; }
    public int R10 { get; set; }
    public int R11 { get; set; }
    public int R12 { get; set; }
    public int SP_R13 { get; set; }
    public int LR_R14 { get; set; }
    public int PC_R15 { get; set; }
    public int CPSR { get; set; }

    public override string ToString()
    {
        return
            $"R0:\t{R0:x}\tR8:\t{R8:x}\nR1:\t{R1:x}\tR9:\t{R9:x}\nR2:\t{R2:x}\tR10:\t{R10:x}\nR3:\t{R3:x}\tR11:\t{R11:x}\nR4:\t{R4:x}\tR12:\t{R12:x}\nR5:\t{R5:x}\tSP:\t{SP_R13:x}\nR6:\t{R6:x}\tLR:\t{LR_R14:x}\nR7:\t{R7:x}\tPC:\t{PC_R15:x}\nCPSR: {CPSR:x16}";
    }
}
