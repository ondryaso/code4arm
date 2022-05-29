// AutoMapperExtensions.cs
// Author: Ondřej Ondryáš

using AutoMapper;

namespace Code4Arm.ExecutionService.MapperConfiguration;

public static class AutoMapperExtensions
{
    public static void CreateNullableMap<T>(this IProfileExpression profile) where T : struct
    {
        profile.CreateMap<T?, T>().ConvertUsing<NullableConverter<T>>();
    }

    public static void IgnoreNullSourceProperties<TSource, TDestination>(this IMappingExpression<TSource, TDestination> expression)
    {
        expression.ForAllMembers(o =>
        {
            o.AllowNull();
            o.Condition((_, _, srcMember) => srcMember != null);
        });
    }
}

public class NullableConverter<T> : ITypeConverter<Nullable<T>, T> where T : struct
{
    public T Convert(T? source, T destination, ResolutionContext context)
    {
        return source ?? destination;
    }
}
