namespace Code4Arm.Unicorn;

public class UnicornException : Exception
{
    public int ErrorId { get; }

    internal UnicornException(int errorId, string message)
        : base(message)
    {
        this.ErrorId = errorId;
    }
}