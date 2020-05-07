using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using JsonWebKey = Microsoft.IdentityModel.Tokens.JsonWebKey;

namespace IdentityServer4.Contrib.Certificates.Stores
{
    public class InMemoryWebHostingCertificatesStore : ISigningCredentialStore, IValidationKeysStore
    {
        private string _hostname;

        private X509Certificate2 certificate = null;

        protected readonly ILogger Logger;

        private Dictionary<X509Certificate2, SecurityKeyInfo> inMemorySecurityKeyInfoStore;
        public InMemoryWebHostingCertificatesStore(IdentityServerOptions options, ILogger<InMemoryWebHostingCertificatesStore> logger)
        {
            _hostname = new Uri(options.IssuerUri).Host;
            Logger = logger;

            inMemorySecurityKeyInfoStore = new Dictionary<X509Certificate2, SecurityKeyInfo>();

            GetSigningCredentials();
        }
        public Task<SigningCredentials> GetSigningCredentialsAsync()
        {
            return Task.FromResult(GetSigningCredentials());
        }

        public Task<IEnumerable<SecurityKeyInfo>> GetValidationKeysAsync()
        {
            foreach (var key in inMemorySecurityKeyInfoStore.Keys.Where(i => !i.Verify()))
            {
                inMemorySecurityKeyInfoStore.Remove(key);
                Logger.LogInformation(
                    $"The certificate {key.Subject} has been removed from ValidationKeys (expiration date {key.GetExpirationDateString()}).");
            }

            return Task.FromResult(inMemorySecurityKeyInfoStore.Values.AsEnumerable());
        }

        private SigningCredentials GetSigningCredentials()
        {
            using (X509Store store = new X509Store("WebHosting", StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);

                var certs = store.Certificates.Find(X509FindType.FindBySubjectName, _hostname, true);

                if (certs.Count > 0)
                {
                    var validCert = certs[0];

                    var toAdd = false;

                    if (certificate == null)
                    {
                        certificate = validCert;

                        toAdd = true;

                        Logger.LogInformation(
                                $"The certificate {validCert.Subject} has been found with expiration date {validCert.GetExpirationDateString()}.");
                    }
                    else if (certificate.Thumbprint != validCert.Thumbprint)
                    {
                        toAdd = true;
                        Logger.LogInformation(
                            $"The new certificate {validCert.Subject} has been found with expiration date {validCert.GetExpirationDateString()}.");

                        certificate = validCert;
                    }


                    if (toAdd)
                    {
                        var credential = MakeSigningCredentials(certificate);

                        inMemorySecurityKeyInfoStore.Add(certificate, new SecurityKeyInfo
                        {
                            Key = credential.Key,
                            SigningAlgorithm = credential.Algorithm
                        });
                    }
                }

                store.Close();
            }

            if (certificate == null)
                throw new Exception($"Unable to find certificate for host {_hostname} in WebHosting LocalMachine X509Store.");

            return MakeSigningCredentials(certificate);
        }

        private SigningCredentials MakeSigningCredentials(X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            if (!certificate.HasPrivateKey)
                throw new InvalidOperationException("X509 certificate does not have a private key.");

            string signingAlgorithm = SecurityAlgorithms.RsaSha256;

            // add signing algorithm name to key ID to allow using the same key for two different algorithms (e.g. RS256 and PS56);
            var key = new X509SecurityKey(certificate);
            key.KeyId += signingAlgorithm;

            var credential = new SigningCredentials(key, signingAlgorithm);

            if (!(credential.Key is AsymmetricSecurityKey
                || credential.Key is JsonWebKey && ((JsonWebKey)credential.Key).HasPrivateKey))
            {
                throw new InvalidOperationException("Signing key is not asymmetric");
            }

            if (!IdentityServerConstants.SupportedSigningAlgorithms.Contains(credential.Algorithm, StringComparer.Ordinal))
            {
                throw new InvalidOperationException($"Signing algorithm {credential.Algorithm} is not supported.");
            }

            if (credential.Key is ECDsaSecurityKey skey && !IsValidCurveForAlgorithm(skey, credential.Algorithm))
            {
                throw new InvalidOperationException("Invalid curve for signing algorithm");
            }

            if (credential.Key is JsonWebKey jsonWebKey)
            {
                if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve && !IsValidCrvValueForAlgorithm(jsonWebKey.Crv))
                    throw new InvalidOperationException("Invalid crv value for signing algorithm");
            }

            return credential;
        }

        internal static class CurveOids
        {
            public const string P256 = "1.2.840.10045.3.1.7";
            public const string P384 = "1.3.132.0.34";
            public const string P521 = "1.3.132.0.35";
        }

        internal static bool IsValidCurveForAlgorithm(ECDsaSecurityKey key, string algorithm)
        {
            var parameters = key.ECDsa.ExportParameters(false);

            if (algorithm == SecurityAlgorithms.EcdsaSha256 && parameters.Curve.Oid.Value != CurveOids.P256
                || algorithm == SecurityAlgorithms.EcdsaSha384 && parameters.Curve.Oid.Value != CurveOids.P384
                || algorithm == SecurityAlgorithms.EcdsaSha512 && parameters.Curve.Oid.Value != CurveOids.P521)
            {
                return false;
            }

            return true;
        }
        internal static bool IsValidCrvValueForAlgorithm(string crv)
        {
            return crv == JsonWebKeyECTypes.P256 ||
                   crv == JsonWebKeyECTypes.P384 ||
                   crv == JsonWebKeyECTypes.P521;
        }
    }
}
