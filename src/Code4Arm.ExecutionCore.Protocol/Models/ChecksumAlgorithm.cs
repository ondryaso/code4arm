using Code4Arm.ExecutionCore.Protocol.StringEnum;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// Names of checksum algorithms that may be supported by a debug adapter.
/// </summary>
public class ChecksumAlgorithm : StringEnum<ChecksumAlgorithm>
{
    public static readonly ChecksumAlgorithm Md5 = Create("MD5");
    public static readonly ChecksumAlgorithm Sha1 = Create("SHA1");
    public static readonly ChecksumAlgorithm Sha256 = Create("SHA256");
    public static readonly ChecksumAlgorithm Timestamp = Create("timestamp");
}
