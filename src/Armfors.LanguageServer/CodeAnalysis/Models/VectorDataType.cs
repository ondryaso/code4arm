namespace Armfors.LanguageServer.CodeAnalysis.Models;

public enum VectorDataType
{
    // Signed or unsigned integer of <size> bits
    I8 = 0 + 8,
    I16 = 0 + 16,
    I32 = 0 + 32,
    I64 = 0 + 64,

    // Signed integer of <size> bits
    S8 = 1 + 8,
    S16 = 1 + 16,
    S32 = 1 + 32,
    S64 = 1 + 64,

    // Unsigned integer of <size> bits
    U8 = 2 + 8,
    U16 = 2 + 16,
    U32 = 2 + 32,
    U64 = 2 + 64,

    // Polynomial over {0, 1} of degree less than <size>
    P8 = 3 + 8,
    P16 = 3 + 16,

    // Floating-point number of <size> bits
    F16 = 4 + 16,
    F32 = 4 + 32,
    F64 = 4 + 64,

    // Any element of <size> bits (specifier: .<size>)
    Any8 = 5 + 8,
    Any16 = 5 + 16,
    Any32 = 5 + 32,
    Any64 = 5 + 64,

    // Unknown value, used in GetVectorDataType(string) 
    Unknown = 5
}

public enum VectorDataTypeCategory
{
    AnyInteger = 0,
    Signed = 1,
    Unsigned = 2,
    Polynomial = 3,
    FloatingPoint = 4,
    Any = 5
}

public static class VectorDataTypeExtensions
{
    public static uint GetElementSize(this VectorDataType dataType)
    {
        return ((uint)dataType) & ~7u;
    }

    public static VectorDataTypeCategory GetCategory(this VectorDataType dataType)
    {
        return (VectorDataTypeCategory)((uint)dataType & 7u);
    }

    public static string GetTextForm(this VectorDataType dataType)
    {
        return dataType switch
        {
            VectorDataType.Any8 => "8",
            VectorDataType.Any16 => "16",
            VectorDataType.Any32 => "32",
            VectorDataType.Any64 => "64",
            _ => dataType.ToString()
        };
    }

    public static VectorDataType GetVectorDataType(string dataType)
    {
        return dataType switch
        {
            "8" => VectorDataType.Any8,
            "16" => VectorDataType.Any16,
            "32" => VectorDataType.Any32,
            "64" => VectorDataType.Any64,
            _ => (Enum.TryParse(dataType, true, out VectorDataType result) &&
                  (Enum.GetName(typeof(VectorDataType), result)?.Equals(dataType,
                      StringComparison.InvariantCultureIgnoreCase) ?? false))
                ? result
                : VectorDataType.Unknown
        };
    }
}
