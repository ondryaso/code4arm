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
        this.CreateMap<StackPlacementOptions[], StackPlacementOptions>()
            .ConstructUsing(arr => arr.Length == 0 ? 0 : arr.Aggregate((i, j) => i | j));

        this.CreateMap<ExecutionOptionsOverlay, ExecutionOptions>()
            .IgnoreNullSourceProperties();

        this.CreateMap<ExecutionOptionsOverlay, ExecutionOptionsOverlay>()
            .IgnoreNullSourceProperties();

        this.CreateMap<ExecutionOptions, ExecutionOptions>();
    }
}
