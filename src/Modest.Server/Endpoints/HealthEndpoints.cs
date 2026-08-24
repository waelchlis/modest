using Modest.Core.Issuance;

namespace Modest.Server.Endpoints;

/// <summary>
/// Operational endpoints, served on the plain-HTTP listener rather than the EST one.
/// </summary>
/// <remarks>
/// Separated so that a Kubernetes kubelet can probe them without performing a TLS handshake or
/// being dragged into client certificate negotiation. See the listener configuration in
/// <c>Program.cs</c>.
/// </remarks>
public static class HealthEndpoints
{
    public static void MapHealthEndpoints(this IEndpointRouteBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Liveness: the process is running and can serve. Deliberately checks no dependency —
        // a liveness probe that fails on a downstream outage restarts a perfectly healthy pod.
        builder.MapGet("/healthz", static () => Results.Text("ok", "text/plain"));

        builder.MapGet("/readyz", static async (
            ICertificateIssuer issuer, CancellationToken cancellationToken) =>
        {
            bool ready;
            try
            {
                ready = await issuer.IsReadyAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                ready = false;
            }

            return ready
                ? Results.Text("ready", "text/plain")
                : Results.Text("not ready", "text/plain", statusCode: StatusCodes.Status503ServiceUnavailable);
        });
    }
}
