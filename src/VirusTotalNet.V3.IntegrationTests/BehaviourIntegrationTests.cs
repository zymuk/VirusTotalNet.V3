using VirusTotalNet.V3.Core;
using Xunit.Abstractions;

namespace VirusTotalNet.V3.IntegrationTests;

[Trait(TestKey.TraitCategory, "Integration")]
public class BehaviourIntegrationTests
{
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private readonly ITestOutputHelper _output;

    public BehaviourIntegrationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [SkippableFact]
    public async Task GetBehaviour_FileWithSandboxData()
    {
        TestKey.SkipIfUnavailable();

        using var vt = new VirusTotal(TestKey.CreateOptions());

        try
        {
            var behaviour = await vt.GetBehaviourAsync(EicarSha256);
            Assert.NotNull(behaviour);
            Assert.NotNull(behaviour.Attributes);
        }
        catch (VtHttpException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            // No sandbox behaviour data for EICAR sample — note it, do not fail (per STATUS.md #3)
            _output.WriteLine($"No behaviour data for EICAR sample (expected possible): {ex.Message}");
        }
    }
}