// DebuggerOptionsMapperProfile.cs
// Author: Ondřej Ondryáš

using System.Text;
using AutoMapper;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionService.ClientConfiguration;

namespace Code4Arm.ExecutionService.MapperConfiguration;

public class DebuggerOptionsMapperProfile : Profile
{
    public DebuggerOptionsMapperProfile()
    {
        this.CreateMap<ArmSimdRegisterVariableOptionsOverlay, ArmSimdRegisterVariableOptions>()
            .IgnoreNullSourceProperties();

        this.CreateMap<DebuggerOptionsOverlay, DebuggerOptions>()
            .ForMember(dst => dst.CStringEncoding, o =>
                o.MapFrom((src, dst) =>
                    src.CStringEncoding == null ? null : Encoding.GetEncoding(src.CStringEncoding)))
            .IgnoreNullSourceProperties();

        this.CreateMap<DebuggerOptionsOverlay, DebuggerOptionsOverlay>()
            .IgnoreNullSourceProperties();
    }
}
