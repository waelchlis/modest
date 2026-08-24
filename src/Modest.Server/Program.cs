using Microsoft.Extensions.Options;
using Modest.Issuance.HttpDelegate;
using Modest.Issuance.InternalCa;
using Modest.Server;

try
{
    WebApplication app = ModestHost.Build(args);
    await app.RunAsync();
    return 0;
}
catch (CaKeyLoadException ex)
{
    // Fail closed and say exactly what is wrong. An EST server that cannot sign must not start and
    // then report itself healthy.
    Console.Error.WriteLine($"modest: cannot start: {ex.Message}");
    if (ex.InnerException is not null)
    {
        Console.Error.WriteLine($"modest: cause: {ex.InnerException.Message}");
    }

    return 1;
}
catch (PkiConfigurationException ex)
{
    Console.Error.WriteLine($"modest: cannot start: {ex.Message}");
    return 1;
}
catch (OptionsValidationException ex)
{
    Console.Error.WriteLine("modest: cannot start: configuration is invalid:");
    foreach (string failure in ex.Failures)
    {
        Console.Error.WriteLine($"  - {failure}");
    }

    return 1;
}
catch (InvalidOperationException ex)
{
    Console.Error.WriteLine($"modest: cannot start: {ex.Message}");
    return 1;
}

/// <summary>Exposed so the integration test host can reference this assembly's entry point.</summary>
public partial class Program;
