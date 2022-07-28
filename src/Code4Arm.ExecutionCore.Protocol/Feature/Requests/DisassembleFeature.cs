// DisassembleFeature.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// 
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// Copyright (c) .NET Foundation and Contributors
// All Rights Reserved
// 
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Available under the MIT License.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
// to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of
// the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record DisassembleArguments : IRequest<DisassembleResponse>
        {
            /// <summary>
            /// Memory reference to the base location containing the instructions to disassemble.
            /// </summary>
            public string MemoryReference { get; init; }

            /// <summary>
            /// Optional offset(in bytes) to be applied to the reference location before disassembling.Can be negative.
            /// </summary>
            [Optional]
            public long? Offset { get; init; }

            /// <summary>
            /// Optional offset(in instructions) to be applied after the byte offset(if any) before disassembling.Can be negative.
            /// </summary>

            [Optional]
            public long? InstructionOffset { get; init; }

            /// <summary>
            /// Number of instructions to disassemble starting at the specified location and offset.An adapter must return exactly this
            /// number of instructions - any unavailable instructions
            /// should be replaced with an implementation-defined 'invalid instruction' value.
            /// </summary>
            public long InstructionCount { get; init; }

            /// <summary>
            /// If true, the adapter should attempt to resolve memory addresses and other values to symbolic names.
            /// </summary>
            [Optional]
            public bool ResolveSymbols { get; init; }
        }

        public record DisassembleResponse
        {
            /// <summary>
            /// The list of disassembled instructions.
            /// </summary>
            public Container<DisassembledInstruction> Instructions { get; init; }
        }
    }

    namespace Models
    {
        /// <summary>
        /// DisassembledInstruction
        /// Represents a single disassembled instruction.
        /// </summary>
        public record DisassembledInstruction
        {
            /// <summary>
            /// The address of the instruction. Treated as a hex value if prefixed with '0x', or as a decimal value otherwise.
            /// </summary>
            public string Address { get; init; }

            /// <summary>
            /// Optional raw bytes representing the instruction and its operands, in an implementation-defined format.
            /// </summary>
            [Optional]
            public string? InstructionBytes { get; init; }

            /// <summary>
            /// Text representing the instruction and its operands, in an implementation-defined format.
            /// </summary>
            public string Instruction { get; init; }

            /// <summary>
            /// Name of the symbol that corresponds with the location of this instruction, if any.
            /// </summary>
            [Optional]
            public string? Symbol { get; init; }

            /// <summary>
            /// Source location that corresponds to this instruction, if any. Should always be set (if available) on the first
            /// instruction returned, but can be omitted afterwards if this
            /// instruction maps to the same source file as the previous instruction.
            /// </summary>
            [Optional]
            public Source? Location { get; init; }

            /// <summary>
            /// The line within the source location that corresponds to this instruction, if any.
            /// </summary>
            [Optional]
            public int? Line { get; init; }

            /// <summary>
            /// The column within the line that corresponds to this instruction, if any.
            /// </summary>
            [Optional]
            public int? Column { get; init; }

            /// <summary>
            /// The end line of the range that corresponds to this instruction, if any.
            /// </summary>
            [Optional]
            public int? EndLine { get; init; }

            /// <summary>
            /// The end column of the range that corresponds to this instruction, if any.
            /// </summary>
            [Optional]
            public int? EndColumn { get; init; }
        }
    }
}
