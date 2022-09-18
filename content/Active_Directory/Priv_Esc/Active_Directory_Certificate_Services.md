# ADCS Information
These notes are mainly summarized from the Specterops paper linked below.
https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf


https://tryhackme.com/room/adcertificatetemplates

ADCS is Microsoft's PKI implementation. ADCS is used for several things such as encrypting file systems, creating and verifying digital signatures, and even user authentication. What makes ADCS a good attack vector is that these certificates survive credential rotation. If a compromised account's password is reset or the system reimaged, the attacker created certificate would still be valid providing persistence.

The image below shows the process for certificate generation, taken from the specterops whitepaper. 

![](/images/cs1.png)

ADCS is a privileged function and usually only runs on select DCs. To mitigate the workload of an Admin creating and distributing certificates manually, certificate templates can be created for use. These templates have parameters that specify which users can request a certificate and what is required for it. Detailed in the specterops paper, it has been found that configurations of ADCS can be abused for privilege escalation and persistent access.

## Certificate Breakdown

A certificate is x.509 formatted and contains the following information:

1. Subject - owner of the cert
2. Public Key - associates the subject with a private key stored seperately
3. NotBefore and NotAfter - duration of the cert
4. Serial Number - ID for the cert assigned by the CA
5. Issuer - who issued the cert (CA)
6. SubjectAlternativeName - defines one or more alternate names that the subject may go by
7. Basic Constraints - identifies whether the cert is assigned to a CA or end entity and if there are any contraints
8. Extended Key Usages (EKUs) - OID that describe how the cert will be used. Some commone OIDs:
	* Code Signing (OID 1.3.6.1.5.5.7.3.3) - for signing executable code
	* Encrypting File System (OID 1.3.6.1.4.1.311.10.3.4) - for encrypting file systems
	* Secure Email (1.3.6.1.5.5.7.3.4) - encrypting email
	* Client Authentication (OID 1.3.6.1.5.5.7.3.2) - authentication to another server
	* Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2) - for use in smart card authentiation
	* Server Authentication (OID 1.3.6.1.5.5.7.3.1) - for identifying servers (HTTPS Certificates)
9. Signature Algorithm - specifies the algorithm used to sign the cert
10. Signature - signature of the certificates body, made using the issuer's private key


The CA first creates its own public-private key pair and generates a self signed certificate to use for issuing certificates. Properties of a CA cert is Subject and Issuer are both the CA's name, Basic Constraints are Subject Type=CA and NotBefore/NotAfter are set to 5 years by default. 

## Certificate Locations

There are four locations under the container CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>

1. Certification Authorities - defines trusted root CA certs. For ADCS to consider a cert to be trusted, the cert chain must end with a root CA defined here. The following attributes are applied to these:
	* objectClass is set to certificationAuthority
	* cACertificate property containes the bytes of the CA's certificate
2. Enrollment Services - container defines Enterprise CAs. In an AD environment a client would interact with the Enterprise CA to request a cert. Every enterprise CA has an AD object containing the following attributes:
	* objectClass set to pKIEnrollmentService
	* cACertificate containing the bytes of the CA's certificate
	* dNSHostName sets the DNS host of the CA
	* Certificate Templates field defining the enables templates
3. NTAuthCertificates - This container defines CA certificates that enable authentication to AD. This AD object has the following properties:
	* objectClass is set to certificationAuthority
	* cACertificate defines an array of trusted CA certs
4. AIA (Authority Information Access) - this container holds AD objects of intermediate and cross CAs (intermediate = children of root CAs).
	* objectClass is set to certificationAuthority
	* cACertificate property containes the bytes of the CA's certificate

## EKUs That Allow Authentication

1. Client Authentication - 1.3.6.1.5.5.7.3.2
2. PKINIT Client Authentication (not enabled by default) - 1.3.6.1.5.2.3.4
3. Smart Card Logon - 1.3.6.1.4.1.311.20.2.2
4. Any Purpose - 2.5.29.37.0
5. SubCA - (no EKUs)


## Enrollment Rights

Enrollment rights in ADCS are defined by two security descriptors: one on the certificate template and one on the Enterprice CA.

The following ACEs within a templates DACL will allow a principal enrollment rights:
1. Certificate Enrollment extended right - The raw ACE grants a principal RIGHT_DS_CONTROL_ACCESS where the Object Type is set to 0e10c968-78fb-11d2-90d4-00c04f79dc55
2. Certificate-AutoEnrollment extended right - The raw ACE grants a principal RIGHT_DS_CONTROL_ACCESS where the Object Type is set to 05b8cc2 -17bc-4802-a710-e7c15ab866a2
3. All ExtendedRights - The raw ACE grants a principal RIGHT_DS_CONTROL_ACCESS where the Object Type is set to 0000000-
0000-0000-0000-000000000000
4. FullControl/GenericAll

The Enterprise CA also stores these, but supersedes the certificate templates.


## Subject Alternative Names and Authentication

SANs are a way to specify an additional identity to be bound to a certificate. Example being a web server that hosts multiple domains. One certificate would be suffecient for this server by specifying the other domains in the SAN. This ability being combined with domain authentication is dangerous. Taken from the specterops paper:

`By default, during certificate-based authentication, one way AD maps certificates to user accounts based on a UPN specified in the
SAN. If an attacker can specify an arbitrary SAN when requesting a certificate that has an EKU enabling client authentication, and the CA creates and signs a certificate using the attacker-supplied SAN, the attacker can become any user in the domain.`



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

# Account Persistence

## Persist1 - Active User Credential Theft via Certificates

If an enterprise CA does exist a user can request a certificate for any template available to them for enrollment. The template must have the following properties:

1. published for enrollment
2. domain users are allowed to enroll
3. has any of the following EKUs
	* Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
	* Client Authentication (1.3.6.1.5.5.7.3.2)
	* PKINIT Client Authentication (1.3.6.1.5.2.3.4)
	* Any Purpose EKU (2.5.29.37.0)
	* No EKU set. i.e., this is a (subordinate) CA certificate.
4. does not require manager approval or authorized signatures

There is a "User" template which is a stock template that allows this. It is enabled by default. 

Using Certify with the /clientauth command will show all available templates to the user with these parameters. 

```
Certify.exe /clientauth
```

If GUI access is available, we can manually request a certificate through certmgr.msc or certreq.exe. Certify can also be used to enroll the current user in a new certificat template. 

```
Certify.exe request /ca:CA_SERVER\CA-NAME /template:template-name
Certify.exe request /ca:dc01.domain.local\dc01-CA /template:User
```

This will output a .pem file, openssl can be used to transfer this to a .pfx. The .pfx can be transferred to a target and used with Rubeus to request a TGT for the enrolled user. 

```
Rubeus.exe asktgt /user:username /certificate:C:\Temp\cert.pfx /password:password123!
```
This allows persistence as this user for as long as the ceritifcate is valid. Looking back at Theft5, this allows persistent access to the user's NTLM hash


## Persist2 - Machine Persistence via Certificates

