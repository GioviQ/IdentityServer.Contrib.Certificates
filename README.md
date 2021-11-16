# IdentityServer4.Contrib.Certificates
Add WebHosting Certificate to IdentityServer

In your Startup.cs after var identityServerBuilder = services.AddIdentityServer(... etc.


simply add

```
identityServerBuilder.AddWebHostingCertificate();
```
In WebHosting LocalMachine X509Store a certificate with Subject equal to hostname of Identity Server IssuerUri must be present.


If you use [win-acme](https://github.com/win-acme/win-acme) to get a certificate for your web application, this Identity Server extension is the perfect companion to keep Identity Server Signin Credential up to date.

IIS_IUSRS group has to access Windows Certificate Store where win-acme will store the certificate. So use the following command:

```
wacs.exe --acl-fullcontrol "iis_iusrs,administrators"
```
