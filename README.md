# IdentityServer4.Contrib.Certificates
Add WebHosting Certificate to IdentityServer

In your Startup.cs after var identityServerBuilder = services.AddIdentityServer(...
simply add

```
identityServerBuilder.AddWebHostingCertificate();
```

