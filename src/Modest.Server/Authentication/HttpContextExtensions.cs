using Modest.Core.Issuance;

namespace Modest.Server.Authentication;

public static class HttpContextExtensions
{
    /// <summary>
    /// The EST client identity resolved by <see cref="EstAuthenticationMiddleware"/>.
    /// </summary>
    /// <remarks>
    /// Returns <see cref="ClientIdentity.Anonymous"/> when the middleware has not run, so a routing
    /// mistake fails closed — an endpoint reached without authentication is treated as
    /// unauthenticated rather than silently trusted.
    /// </remarks>
    public static ClientIdentity GetEstClientIdentity(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Items.TryGetValue(EstAuthenticationMiddleware.IdentityItemKey, out object? value) &&
               value is ClientIdentity identity
            ? identity
            : ClientIdentity.Anonymous;
    }
}
