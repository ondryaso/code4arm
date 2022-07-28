// NullableMapperProfile.cs
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

using AutoMapper;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Debugger;

namespace Code4Arm.ExecutionService.MapperConfiguration;

public class NullableMapperProfile : Profile
{
    public NullableMapperProfile()
    {
        this.CreateNullableMap<int>();
        this.CreateNullableMap<bool>();
        this.CreateNullableMap<uint>();
        this.CreateNullableMap<VariableNumberFormat>();
        this.CreateNullableMap<SimdRegisterLevel>();
        this.CreateNullableMap<StackPlacementOptions>();
        this.CreateNullableMap<StackPointerType>();
        this.CreateNullableMap<RegisterInitOptions>();
        this.CreateNullableMap<StepBackMode>();
    }
}
