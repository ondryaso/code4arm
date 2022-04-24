// UnicornError.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.Unicorn.Abstractions.Enums;

public enum UnicornError
{
    Ok = 0,
    OutOfMemory = 1,
    InvalidArchitecture = 2,
    InvalidHandle = 3,
    InvalidMode = 4,
    BindingVersionMismatch = 5,
    ReadUnmapped = 6,
    WriteUnmapped = 7,
    FetchUnmapped = 8,
    InvalidHookType = 9,
    InvalidInstruction = 10,
    InvalidMapping = 11,
    WriteProtected = 12,
    ReadProtected = 13,
    FetchProtected = 14,
    InvalidArgument = 15,
    ReadUnaligned = 16,
    WriteUnaligned = 17,
    FetchUnaligned = 18,
    HookAlreadyExists = 19,
    InsufficientResources = 20,
    UnhandledCpuException = 21
}
