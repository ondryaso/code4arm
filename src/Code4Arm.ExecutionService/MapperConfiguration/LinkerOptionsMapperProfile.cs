// LinkerOptionsMapperProfile.cs
// Author: Ondřej Ondryáš

using AutoMapper;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionService.Services.Abstractions;

namespace Code4Arm.ExecutionService.MapperConfiguration;

public class LinkerOptionsMapperProfile : Profile
{
    public LinkerOptionsMapperProfile()
    {
        this.CreateMap<IClientConfiguration, LinkerOptions>()
            .IgnoreNullSourceProperties();
    }
}
