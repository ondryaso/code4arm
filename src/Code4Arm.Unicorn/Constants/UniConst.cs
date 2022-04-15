namespace Code4Arm.Unicorn.Constants;

public static class UniConst
{
    public static class Arch
    {
        public const int Arm = 1;
        public const int Arm64 = 2;
        public const int Mips = 3;
        public const int X86 = 4;
        public const int Ppc = 5;
        public const int Sparc = 6;
        public const int M68K = 7;
        public const int Riscv = 8;
        public const int Max = 9;
    }

    public static class Err
    {
        public const int Ok = 0;
        public const int Nomem = 1;
        public const int Arch = 2;
        public const int Handle = 3;
        public const int Mode = 4;
        public const int Version = 5;
        public const int ReadUnmapped = 6;
        public const int WriteUnmapped = 7;
        public const int FetchUnmapped = 8;
        public const int Hook = 9;
        public const int InsnInvalid = 10;
        public const int Map = 11;
        public const int WriteProt = 12;
        public const int ReadProt = 13;
        public const int FetchProt = 14;
        public const int Arg = 15;
        public const int ReadUnaligned = 16;
        public const int WriteUnaligned = 17;
        public const int FetchUnaligned = 18;
        public const int HookExist = 19;
        public const int Resource = 20;
        public const int Exception = 21;
    }

    public static class Mem
    {
        public const int Read = 16;
        public const int Write = 17;
        public const int Fetch = 18;
        public const int ReadUnmapped = 19;
        public const int WriteUnmapped = 20;
        public const int FetchUnmapped = 21;
        public const int WriteProt = 22;
        public const int ReadProt = 23;
        public const int FetchProt = 24;
        public const int ReadAfter = 25;
    }

    public static class Tcg
    {
        public const int OpSub = 0;
        public const int OpFlagCmp = 1;
        public const int OpFlagDirect = 2;
    }

    public static class Hook
    {
        public const int Intr = 1;
        public const int Insn = 2;
        public const int Code = 4;
        public const int Block = 8;
        public const int MemReadUnmapped = 16;
        public const int MemWriteUnmapped = 32;
        public const int MemFetchUnmapped = 64;
        public const int MemReadProt = 128;
        public const int MemWriteProt = 256;
        public const int MemFetchProt = 512;
        public const int MemRead = 1024;
        public const int MemWrite = 2048;
        public const int MemFetch = 4096;
        public const int MemReadAfter = 8192;
        public const int InsnInvalid = 16384;
        public const int EdgeGenerated = 32768;
        public const int TcgOpcode = 65536;
        public const int MemUnmapped = 112;
        public const int MemProt = 896;
        public const int MemReadInvalid = 144;
        public const int MemWriteInvalid = 288;
        public const int MemFetchInvalid = 576;
        public const int MemInvalid = 1008;
        public const int MemValid = 7168;
    }

    public static class Query
    {
        public const int Mode = 1;
        public const int PageSize = 2;
        public const int Arch = 3;
        public const int Timeout = 4;
    }

    public static class Ctl
    {
        public const int Mode = 0;
        public const int PageSize = 1;
        public const int Arch = 2;
        public const int Timeout = 3;
        public const int UseExits = 4;
        public const int ExitsCnt = 5;
        public const int Exits = 6;
        public const int CpuModel = 7;
        public const int TbRequestCache = 8;
        public const int TbRemoveCache = 9;
    }
}