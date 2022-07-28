// MemoryAccessType.cs
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

namespace Code4Arm.Unicorn.Abstractions.Enums;

// Original: uc_mem_type
public enum MemoryAccessType
{
    Read = 16,      // Memory is read from
    Write,          // Memory is written to
    Fetch,          // Memory is fetched
    ReadUnmapped,   // Unmapped memory is read from
    WriteUnmapped,  // Unmapped memory is written to
    FetchUnmapped,  // Unmapped memory is fetched
    WriteProtected, // Write to write protected, but mapped, memory
    ReadProtected,  // Read from read protected, but mapped, memory
    FetchProtected, // Fetch from non-executable, but mapped, memory
    AfterRead       // Memory is read from (successful access)
}
