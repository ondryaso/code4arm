// PoCRegisterStatus.cs
// Author: Ondřej Ondryáš

namespace Armulator.ExecutionService.Hubs;

public class PoCRegisterStatus
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
}
