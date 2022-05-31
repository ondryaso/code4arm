// ExecutionOptionsMapperProfile.cs
// Author: Ondřej Ondryáš

using System.Text;
using AutoMapper;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionService.ClientConfiguration;

namespace Code4Arm.ExecutionService.MapperConfiguration;

public class ExecutionOptionsMapperProfile : Profile
{
    public ExecutionOptionsMapperProfile()
    {
        this.CreateMap<ExecutionOptionsOverlay, ExecutionOptions>()
            .IgnoreNullSourceProperties();

        this.CreateMap<ExecutionOptionsOverlay, ExecutionOptionsOverlay>()
            .IgnoreNullSourceProperties();

        this.CreateMap<ExecutionOptions, ExecutionOptions>();
    }
}
