// RemoteFileMetadata.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionService.Files;

public class RemoteFileMetadata
{
    public string Name { get; set; } = string.Empty;
    public int Version { get; set; }
    public string? Text { get; set; }
}
