// ExceptionMessages.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionService;

public class ExceptionMessages
{
    public const string NoLaunchTarget =
        "No build target specified. Either 'sourceDirectory' or 'sourceFiles' must be present in launch.json";

    public const string Assembling =
        "Cannot assemble {0} source(s). Check output for error details.";

    public const string Linking = "Cannot link assembled objects. Check output for more details.";

    public const string LaunchConfig
        = "Invalid launch configuration.";

    public const string LaunchConfigTimeoutTooSmall
        = $"{LaunchConfig} The minimal allowed execution timeout is {{0}} ms.";

    public const string LaunchConfigTimeoutTooBig
        = $"{LaunchConfig} The maximal allowed execution timeout is {{0}} ms.";

    public const string LaunchConfigInfiniteTimeout
        = $"{LaunchConfig} Infinite timeout is not allowed.";

    public const string LaunchConfigStackSizeTooBig
        = $"{LaunchConfig} The maximal allowed stack size is {{0}} B ({{1}} KiB).";

    public const string LaunchConfigInvalidEncoding
        = $"{LaunchConfig} Invalid C-string encoding specifier.";

    public const string LaunchConfigInvalidAssemblerOption
        = $"{LaunchConfig} Invalid assembler option {{0}}.";

    public const string LaunchConfigInvalidLinkerOption
        = $"{LaunchConfig} Invalid linker option {{0}}.";
}
