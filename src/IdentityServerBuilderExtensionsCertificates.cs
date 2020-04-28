using IdentityServer4.Configuration;
using IdentityServer4.Contrib.Certificates.Stores;
using IdentityServer4.Stores;
using Microsoft.Extensions.Logging;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class IdentityServerBuilderExtensionsCertificates
    {
        /// <summary>
        /// Sets the signing credential finding a valid certificate in WebHosting X509Store with subject equals to hostname of Identity Server Issuer Uri.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="InvalidOperationException">X509 certificate does not have a private key.</exception>
        public static IIdentityServerBuilder AddWebHostingCertificate(this IIdentityServerBuilder builder)
        {
            builder.Services.AddSingleton<ISigningCredentialStore, InMemoryWebHostingCertificatesStore>();

            builder.Services.AddSingleton(s => s.GetRequiredService<ISigningCredentialStore>() as IValidationKeysStore);

            return builder;
        }
    }
}
