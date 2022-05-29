// NullableMapperProfile.cs
// Author: Ondřej Ondryáš

using AutoMapper;
using Code4Arm.ExecutionCore.Execution.Debugger;

namespace Code4Arm.ExecutionService.MapperConfiguration;

public class NullableMapperProfile : Profile
{
    public NullableMapperProfile()
    {
        this.CreateNullableMap<int>();
        this.CreateNullableMap<bool>();
        this.CreateNullableMap<VariableNumberFormat>();
        this.CreateNullableMap<SimdRegisterLevel>();
    }
}
