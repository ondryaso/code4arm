using Code4Arm.ExecutionCore.Protocol.Serialization;
using Code4Arm.ExecutionCore.Protocol.StringEnum;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        public record ProcessEvent : IRequest
        {
            /// <summary>
            /// The logical name of the process. This is usually the full path to process's executable file. Example:
            /// /home/example/myproj/program.js.
            /// </summary>
            public string Name { get; init; }

            /// <summary>
            /// The system process id of the debugged process. This property will be missing for non-system processes.
            /// </summary>
            [Optional]
            public long? SystemProcessId { get; init; }

            /// <summary>
            /// If true, the process is running on the same computer as the debug adapter.
            /// </summary>
            [Optional]
            public bool IsLocalProcess { get; init; }

            /// <summary>
            /// Describes how the debug engine started debugging this process.
            /// 'launch': Process was launched under the debugger.
            /// 'attach': Debugger attached to an existing process.
            /// 'attachForSuspendedLaunch': A project launcher component has launched a new process in a suspended state and then asked
            /// the debugger to attach.
            /// </summary>
            [Optional]
            public ProcessEventStartMethod? StartMethod { get; init; }

            /// <summary>
            /// The size of a pointer or address for this process, in bits. This value may be used by clients when formatting addresses
            /// for display.
            /// </summary>
            [Optional]
            public long? PointerSize { get; init; }
        }

        public class ProcessEventStartMethod : StringEnum<ProcessEventStartMethod>
        {
            public static readonly ProcessEventStartMethod Launch = Create("launch");
            public static readonly ProcessEventStartMethod Attach = Create("attach");

            public static readonly ProcessEventStartMethod AttachForSuspendedLaunch =
                Create("attachForSuspendedLaunch");
        }
    }
}
