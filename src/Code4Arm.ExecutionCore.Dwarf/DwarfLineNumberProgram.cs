// DwarfLineNumberProgram.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// 
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// Copyright (c) 2019 Vuk Jovanovic
// 
// Original source: https://github.com/southpolenator/SharpDebug
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

namespace Code4Arm.ExecutionCore.Dwarf;

/// <summary>
/// Helper class that parses debug line data stream and returns list of file/line information.
/// </summary>
internal class DwarfLineNumberProgram
{
    /// <summary>
    /// The maximum operations per instruction
    /// </summary>
    private const int MaximumOperationsPerInstruction = 1;

    /// <summary>
    /// Gets the list of files.
    /// </summary>
    public List<DwarfFileInformation> Files { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DwarfLineNumberProgram"/> class.
    /// </summary>
    /// <param name="debugLine">The debug line data stream.</param>
    /// <param name="addressNormalizer">Normalize address delegate.</param>
    public DwarfLineNumberProgram(DwarfMemoryReader debugLine, Func<uint, uint> addressNormalizer)
    {
        Files = ReadData(debugLine, addressNormalizer);
    }

    /// <summary>
    /// Reads the data for single instance.
    /// </summary>
    /// <param name="debugLine">The debug line data stream.</param>
    /// <param name="addressNormalizer">Normalize address delegate.</param>
    /// <returns>List of file information.</returns>
    private static List<DwarfFileInformation> ReadData(DwarfMemoryReader debugLine,
        Func<uint, uint> addressNormalizer)
    {
        // Read header
        bool is64bit;
        var beginPosition = debugLine.Position;
        var length = debugLine.ReadLength(out is64bit);
        var endPosition = debugLine.Position + (int)length;
        var version = debugLine.ReadUshort();
        var headerLength = debugLine.ReadOffset(is64bit);
        var minimumInstructionLength = debugLine.ReadByte();
        var defaultIsStatement = debugLine.ReadByte() != 0;
        var lineBase = (sbyte)debugLine.ReadByte();
        var lineRange = debugLine.ReadByte();
        var operationCodeBase = debugLine.ReadByte();

        // Read operation code lengths
        var operationCodeLengths = new uint[operationCodeBase];

        operationCodeLengths[0] = 0;
        for (var i = 1; i < operationCodeLengths.Length && debugLine.Position < endPosition; i++)
        {
            operationCodeLengths[i] = debugLine.Leb128();
        }

        // Read directories
        var directories = new List<string>();

        while (debugLine.Position < endPosition && debugLine.Peek() != 0)
        {
            var directory = debugLine.ReadString();

            directory = directory.Replace('/', Path.DirectorySeparatorChar);
            directories.Add(directory);
        }

        debugLine.ReadByte(); // Skip zero termination byte

        // Read files
        var files = new List<DwarfFileInformation>();

        while (debugLine.Position < endPosition && debugLine.Peek() != 0)
        {
            files.Add(ReadFile(debugLine, directories));
        }

        debugLine.ReadByte(); // Skip zero termination byte

        // Parse lines
        var state = new ParsingState(files.FirstOrDefault(), defaultIsStatement, minimumInstructionLength);
        uint lastAddress = 0;

        while (debugLine.Position < endPosition)
        {
            var operationCode = debugLine.ReadByte();

            if (operationCode >= operationCodeLengths.Length)
            {
                // Special operation code
                var adjustedOperationCode = operationCode - operationCodeBase;
                var operationAdvance = adjustedOperationCode / lineRange;
                state.AdvanceAddress(operationAdvance);
                var lineAdvance = lineBase + (adjustedOperationCode % lineRange);
                state.Line += (uint)lineAdvance;
                state.AddCurrentLineInfo();
                state.IsBasicBlock = false;
                state.IsPrologueEnd = false;
                state.IsEpilogueEnd = false;
                state.Discriminator = 0;
            }
            else
            {
                switch ((DwarfLineNumberStandardOpcode)operationCode)
                {
                    case DwarfLineNumberStandardOpcode.Extended:
                    {
                        var extendedLength = debugLine.Leb128();
                        var newPosition = debugLine.Position + (int)extendedLength;
                        var extendedCode = (DwarfLineNumberExtendedOpcode)debugLine.ReadByte();

                        switch (extendedCode)
                        {
                            case DwarfLineNumberExtendedOpcode.EndSequence:
                                lastAddress = state.Address;
                                state.IsSequenceEnd = true;
                                //state.AddCurrentLineInfo();
                                state.Reset(files.FirstOrDefault());

                                break;
                            case DwarfLineNumberExtendedOpcode.SetAddress:
                            {
                                state.Address = debugLine.ReadUint();
                                if (state.Address == 0)
                                    state.Address = lastAddress;

                                state.OperationIndex = 0;
                            }

                                break;
                            case DwarfLineNumberExtendedOpcode.DefineFile:
                                state.File = ReadFile(debugLine, directories);
                                files.Add(state.File);

                                break;
                            case DwarfLineNumberExtendedOpcode.SetDiscriminator:
                                state.Discriminator = debugLine.Leb128();

                                break;
                            default:
                                throw new Exception($"Unsupported DwarfLineNumberExtendedOpcode: {extendedCode}");
                        }

                        debugLine.Position = newPosition;
                    }

                        break;
                    case DwarfLineNumberStandardOpcode.Copy:
                        state.AddCurrentLineInfo();
                        state.IsBasicBlock = false;
                        state.IsPrologueEnd = false;
                        state.IsEpilogueEnd = false;
                        state.Discriminator = 0;

                        break;
                    case DwarfLineNumberStandardOpcode.AdvancePc:
                        state.AdvanceAddress((int)debugLine.Leb128());

                        break;
                    case DwarfLineNumberStandardOpcode.AdvanceLine:
                        state.Line += debugLine.Sleb128();

                        break;
                    case DwarfLineNumberStandardOpcode.SetFile:
                        state.File = files[(int)debugLine.Leb128() - 1];

                        break;
                    case DwarfLineNumberStandardOpcode.SetColumn:
                        state.Column = debugLine.Leb128();

                        break;
                    case DwarfLineNumberStandardOpcode.NegateStmt:
                        state.IsStatement = !state.IsStatement;

                        break;
                    case DwarfLineNumberStandardOpcode.SetBasicBlock:
                        state.IsBasicBlock = true;

                        break;
                    case DwarfLineNumberStandardOpcode.ConstAddPc:
                        state.AdvanceAddress((255 - operationCodeBase) / lineRange);

                        break;
                    case DwarfLineNumberStandardOpcode.FixedAdvancePc:
                        state.Address += debugLine.ReadUshort();
                        state.OperationIndex = 0;

                        break;
                    case DwarfLineNumberStandardOpcode.SetPrologueEnd:
                        state.IsPrologueEnd = true;

                        break;
                    case DwarfLineNumberStandardOpcode.SetEpilogueBegin:
                        state.IsEpilogueEnd = true;

                        break;
                    case DwarfLineNumberStandardOpcode.SetIsa:
                        state.Isa = debugLine.Leb128();

                        break;
                    default:
                        throw new Exception(
                            $"Unsupported DwarfLineNumberStandardOpcode: {(DwarfLineNumberStandardOpcode)operationCode}");
                }
            }
        }

        // Fix lines in files...
        foreach (var file in files)
        {
            for (var i = 0; i < file.Lines.Count; i++)
            {
                file.Lines[i] = file.Lines[i] with
                {
                    Address = addressNormalizer(file.Lines[i].Address)
                };
            }
        }

        return files;
    }

    /// <summary>
    /// Reads the file information from the specified stream.
    /// </summary>
    /// <param name="debugLine">The debug line data stream.</param>
    /// <param name="directories">The list of existing directories.</param>
    private static DwarfFileInformation ReadFile(DwarfMemoryReader debugLine, List<string> directories)
    {
        var name = debugLine.ReadString();
        var directoryIndex = (int)debugLine.Leb128();
        var lastModification = debugLine.Leb128();
        var length = debugLine.Leb128();
        var directory = directoryIndex > 0 ? directories[directoryIndex - 1] : null;
        var path = name;

        try
        {
            path = string.IsNullOrEmpty(directory) || Path.IsPathRooted(path)
                ? name
                : Path.Combine(directory, name);
        }
        catch
        {
        }

        return new DwarfFileInformation
        {
            Name = name,
            Directory = directory,
            Path = path,
            LastModification = lastModification,
            Length = length
        };
    }

    /// <summary>
    /// Helper class that stores current parsing state information.
    /// </summary>
    private class ParsingState
    {
        /// <summary>
        /// Gets or sets the file.
        /// </summary>
        public DwarfFileInformation File { get; set; }

        /// <summary>
        /// Gets or sets the address.
        /// </summary>
        public uint Address { get; set; }

        /// <summary>
        /// Gets or sets the index of the operation.
        /// </summary>
        public uint OperationIndex { get; set; }

        /// <summary>
        /// Gets or sets the line.
        /// </summary>
        public uint Line { get; set; }

        /// <summary>
        /// Gets or sets the column.
        /// </summary>
        public uint Column { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether we are at statement.
        /// </summary>
        public bool IsStatement { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether we are inside the basic block.
        /// </summary>
        public bool IsBasicBlock { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether sequence has ended.
        /// </summary>
        public bool IsSequenceEnd { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether prologue has ended.
        /// </summary>
        public bool IsPrologueEnd { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether epilogue has ended.
        /// </summary>
        public bool IsEpilogueEnd { get; set; }

        /// <summary>
        /// Gets or sets the ISA.
        /// </summary>
        public uint Isa { get; set; }

        /// <summary>
        /// Gets or sets the discriminator.
        /// </summary>
        public uint Discriminator { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether reset is defaulting to statement.
        /// </summary>
        internal bool DefaultIsStatement { get; }

        /// <summary>
        /// Gets or sets the minimum length of the instruction.
        /// </summary>
        internal byte MinimumInstructionLength { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ParsingState"/> class.
        /// </summary>
        /// <param name="defaultFile">The default file.</param>
        /// <param name="defaultIsStatement">if set to <c>true</c> defaulting to statement during reset.</param>
        /// <param name="minimumInstructionLength">Minimum length of the instruction.</param>
        public ParsingState(DwarfFileInformation defaultFile, bool defaultIsStatement,
            byte minimumInstructionLength)
        {
            DefaultIsStatement = defaultIsStatement;
            MinimumInstructionLength = minimumInstructionLength;
            this.Reset(defaultFile);
        }

        /// <summary>
        /// Resets the parse state and default to the specified file.
        /// </summary>
        /// <param name="defaultFile">The default file.</param>
        public void Reset(DwarfFileInformation defaultFile)
        {
            Address = 0;
            OperationIndex = 0;
            File = defaultFile;
            Line = 1;
            Column = 0;
            IsStatement = DefaultIsStatement;
            IsBasicBlock = false;
            IsSequenceEnd = false;
            IsPrologueEnd = false;
            IsEpilogueEnd = false;
            Isa = 0;
            Discriminator = 0;
        }

        /// <summary>
        /// Advances the address.
        /// </summary>
        /// <param name="operationAdvance">The operation advance.</param>
        public void AdvanceAddress(int operationAdvance)
        {
            var addressAdvance = MinimumInstructionLength *
                (((int)OperationIndex + operationAdvance) / MaximumOperationsPerInstruction);

            Address += (uint)addressAdvance;
            OperationIndex = (OperationIndex + (uint)operationAdvance) % MaximumOperationsPerInstruction;
        }

        /// <summary>
        /// Adds the current line information.
        /// </summary>
        public void AddCurrentLineInfo()
        {
            File.Lines.Add(new DwarfLineInformation
            {
                File = File,
                Address = Address,
                Column = Column,
                Line = Line
            });
        }
    }
}
