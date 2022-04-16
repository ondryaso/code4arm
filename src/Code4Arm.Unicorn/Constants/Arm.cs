// ReSharper disable InconsistentNaming

namespace Code4Arm.Unicorn.Constants;

public static class Arm
{
    public static class Register
    {
        public const int Invalid = 0;
        public const int APSR = 1;
        public const int APSR_NZCV = 2;
        public const int CPSR = 3;
        public const int FPEXC = 4;
        public const int FPINST = 5;
        public const int FPSCR = 6;
        public const int FPSCR_NZCV = 7;
        public const int FPSID = 8;
        public const int ITSTATE = 9;
        public const int LR = 10;
        public const int R14 = 10;
        public const int R15 = 11;
        public const int PC = 11;
        public const int R13 = 12;
        public const int SP = 12;
        public const int SPSR = 13;
        public const int D0 = 14;
        public const int D1 = 15;
        public const int D2 = 16;
        public const int D3 = 17;
        public const int D4 = 18;
        public const int D5 = 19;
        public const int D6 = 20;
        public const int D7 = 21;
        public const int D8 = 22;
        public const int D9 = 23;
        public const int D10 = 24;
        public const int D11 = 25;
        public const int D12 = 26;
        public const int D13 = 27;
        public const int D14 = 28;
        public const int D15 = 29;
        public const int D16 = 30;
        public const int D17 = 31;
        public const int D18 = 32;
        public const int D19 = 33;
        public const int D20 = 34;
        public const int D21 = 35;
        public const int D22 = 36;
        public const int D23 = 37;
        public const int D24 = 38;
        public const int D25 = 39;
        public const int D26 = 40;
        public const int D27 = 41;
        public const int D28 = 42;
        public const int D29 = 43;
        public const int D30 = 44;
        public const int D31 = 45;
        public const int FPINST2 = 46;
        public const int MVFR0 = 47;
        public const int MVFR1 = 48;
        public const int MVFR2 = 49;
        public const int Q0 = 50;
        public const int Q1 = 51;
        public const int Q2 = 52;
        public const int Q3 = 53;
        public const int Q4 = 54;
        public const int Q5 = 55;
        public const int Q6 = 56;
        public const int Q7 = 57;
        public const int Q8 = 58;
        public const int Q9 = 59;
        public const int Q10 = 60;
        public const int Q11 = 61;
        public const int Q12 = 62;
        public const int Q13 = 63;
        public const int Q14 = 64;
        public const int Q15 = 65;
        public const int R0 = 66;
        public const int R1 = 67;
        public const int R2 = 68;
        public const int R3 = 69;
        public const int R4 = 70;
        public const int R5 = 71;
        public const int R6 = 72;
        public const int R7 = 73;
        public const int R8 = 74;
        public const int R9 = 75;
        public const int SB = 75;
        public const int R10 = 76;
        public const int SL = 76;
        public const int FP = 77;
        public const int R11 = 77;
        public const int R12 = 78;
        public const int IP = 78;
        public const int S0 = 79;
        public const int S1 = 80;
        public const int S2 = 81;
        public const int S3 = 82;
        public const int S4 = 83;
        public const int S5 = 84;
        public const int S6 = 85;
        public const int S7 = 86;
        public const int S8 = 87;
        public const int S9 = 88;
        public const int S10 = 89;
        public const int S11 = 90;
        public const int S12 = 91;
        public const int S13 = 92;
        public const int S14 = 93;
        public const int S15 = 94;
        public const int S16 = 95;
        public const int S17 = 96;
        public const int S18 = 97;
        public const int S19 = 98;
        public const int S20 = 99;
        public const int S21 = 100;
        public const int S22 = 101;
        public const int S23 = 102;
        public const int S24 = 103;
        public const int S25 = 104;
        public const int S26 = 105;
        public const int S27 = 106;
        public const int S28 = 107;
        public const int S29 = 108;
        public const int S30 = 109;
        public const int S31 = 110;

        [Obsolete($"Use {nameof(CP_REG)} instead.")]
        public const int C1_C0_2 = 111;

        [Obsolete($"Use {nameof(CP_REG)} instead.")]
        public const int C13_C0_2 = 112;

        [Obsolete($"Use {nameof(CP_REG)} instead.")]
        public const int C13_C0_3 = 113;

        public const int IPSR = 114;
        public const int MSP = 115;
        public const int PSP = 116;
        public const int Control = 117;
        public const int IAPSR = 118;
        public const int EAPSR = 119;
        public const int XPSR = 120;
        public const int EPSR = 121;
        public const int IEPSR = 122;
        public const int PriMask = 123;
        public const int BasePri = 124;
        public const int BasePriMax = 125;
        public const int FaultMask = 126;
        public const int APSR_NZCVQ = 127;
        public const int APSR_G = 128;
        public const int APSR_NZCVQG = 129;
        public const int IAPSR_NZCVQ = 130;
        public const int IAPSR_G = 131;
        public const int IAPSR_NZCVQG = 132;
        public const int EAPSR_NZCVQ = 133;
        public const int EAPSR_G = 134;
        public const int EAPSR_NZCVQG = 135;
        public const int XPSR_NZCVQ = 136;
        public const int XPSR_G = 137;
        public const int XPSR_NZCVQG = 138;
        public const int CP_REG = 139;
        public const int Ending = 140;
    }

    public static class Cpu
    {
        public const int Arm926 = 0;
        public const int Arm946 = 1;
        public const int Arm1026 = 2;
        public const int Arm1136_R2 = 3;
        public const int Arm1136 = 4;
        public const int Arm1176 = 5;
        public const int Arm11MPCORE = 6;
        public const int CortexM0 = 7;
        public const int CortexM3 = 8;
        public const int CortexM4 = 9;
        public const int CortexM7 = 10;
        public const int CortexM33 = 11;
        public const int CortexR5 = 12;
        public const int CortexR5F = 13;
        public const int CortexA7 = 14;
        public const int CortexA8 = 15;
        public const int CortexA9 = 16;
        public const int CortexA15 = 17;
        public const int TI925T = 18;
        public const int SA1100 = 19;
        public const int SA1110 = 20;
        public const int PXA250 = 21;
        public const int PXA255 = 22;
        public const int PXA260 = 23;
        public const int PXA261 = 24;
        public const int PXA262 = 25;
        public const int PXA270 = 26;
        public const int PXA270A0 = 27;
        public const int PXA270A1 = 28;
        public const int PXA270B0 = 29;
        public const int PXA270B1 = 30;
        public const int PXA270C0 = 31;
        public const int PXA270C5 = 32;
        public const int MAX = 33;
    }
}