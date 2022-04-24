using Code4Arm.Unicorn.Abstractions.Enums;

namespace Code4Arm.Unicorn;

public class UnicornException : Exception
{
    public int ErrorId { get; }
    public UnicornError Error { get; }

    internal UnicornException(int errorId, string message)
        : base(message)
    {
        ErrorId = errorId;
        Error = (UnicornError)errorId;
    }
}
