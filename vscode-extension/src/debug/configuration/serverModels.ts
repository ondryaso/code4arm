// serverModels.ts
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

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