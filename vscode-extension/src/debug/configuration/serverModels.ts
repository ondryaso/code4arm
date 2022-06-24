export type StackPlacementOptions = 'FixedAddress' | 'RandomizeAddress' | 'AlwaysKeepFirstAddress'
    | 'ClearData' | 'RandomizeData' | 'KeepData';

export type RegisterInitOptions = 'Clear' | 'Randomize' | 'Keep' | 'RandomizeFirst';

export type StackPointerType = 'FullDescending' | 'FullAscending' | 'EmptyDescending' | 'EmptyAscending';

export type StepBackMode = 'None' | 'CaptureOnStep';

export type VariableNumberFormat = 'Decimal' | 'Hex' | 'Binary' | 'Float';

export type DebuggerVariableType = 'ByteU' | 'ByteS' | 'CharAscii' | 'ShortU' | 'ShortS' | 'IntU'
    | 'IntS' | 'LongU' | 'LongS' | 'Float' | 'Double';

export type SimdRegisterLevel = 'S32' | 'D64' | 'Q128';

export interface ArmSimdRegisterVariableOptionsOverlay {
    qSubtypes?: DebuggerVariableType[];
    dSubtypes?: DebuggerVariableType[];
    sSubtypes?: DebuggerVariableType[];

    showD?: boolean;
    showS?: boolean;

    sIeeeSubvariables?: boolean;
    dIeeeSubvariables?: boolean;

    preferFloatRendering?: boolean;
}

export interface DebuggerOptionsOverlay {
    enableAutomaticDataVariables?: boolean;
    enableStackVariables?: boolean;
    enableRegistersVariables?: boolean;
    enableSimdVariables?: boolean;
    enableControlVariables?: boolean;
    enableExtendedControlVariables?: boolean;

    padUnsignedBinaryNumbers?: boolean;
    variableNumberFormat?: VariableNumberFormat;
    registersSubtypes?: DebuggerVariableType[];
    stackVariablesSubtypes?: DebuggerVariableType[];

    showFloatIeeeSubvariables?: boolean;
    topSimdRegistersLevel?: SimdRegisterLevel;
    simdRegistersOptions?: ArmSimdRegisterVariableOptionsOverlay;

    cStringMaxLength?: number;
    cStringEncoding?: string;
}

export interface ExecutionOptionsOverlay {
    timeout?: number;
    stackSize?: number;
    forcedStackAddress?: number;
    stackPlacementOptions?: StackPlacementOptions[];
    stackPointerType?: StackPointerType[];
    randomizeExtraAllocatedSpaceContents?: boolean;
    useStrictMemoryAccess?: boolean;
    enableAccurateExecutionTracking?: boolean;
    registerInitOptions?: RegisterInitOptions;
    simdRegisterInitOptions?: RegisterInitOptions;
    stepBackMode?: StepBackMode;
}

export interface IClientConfiguration {
    debuggerOptions?: DebuggerOptionsOverlay;
    executionOptions?: ExecutionOptionsOverlay;

    assemblerOptions?: string[];
    ldOptions?: string[];
    ldTrailOptions?: string[];
    trampolineStartAddress?: number;
    trampolineStartEnd?: number;
}