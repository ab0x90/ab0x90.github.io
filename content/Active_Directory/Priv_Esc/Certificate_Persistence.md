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

