namespace Code4Arm.Unicorn.Abstractions.Enums;

[Flags]
public enum MemoryPermissions
{
    None = 0,
    Read = 1,
    Write = 2,
    Exec = 4,
    All = 7
}