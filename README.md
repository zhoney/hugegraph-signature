# hugegraph-signature

## Generate License

Execute `com.baidu.hugegraph.cmd.GenerateLicense` then it will output a license file specified by 'license_path' in config.

## Install License

Implement LicenseManagerFactory:

```java
public class LicenseManagerFactory {

    public static LicenseManager create(LicenseInstallParam param,
                                        VerifyCallback veryfyCallback) {
        return new TrueLicenseManager(param, veryfyCallback);
    }
}
```

Construct LicenseInstallParam from config file, then create LicenseManager from LicenseInstallParam, and call LicenseManager.installLicense() to install license.

```java
LicenseInstallParam param = readFromJsonConfig("verify-license.json");
LicenseManager manager = LicenseManagerFactory.create(param, verifyCallback);
manager.installLicense();
```
