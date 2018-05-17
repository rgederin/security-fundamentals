# TLS/SSL

Transport Layer Security (TLS) – and its predecessor, Secure Sockets Layer (SSL), which is now deprecated by the Internet Engineering Task Force (IETF) – are cryptographic protocols that provide communications security over a computer network. Several versions of the protocols find widespread use in applications such as web browsing, mail, instant messaging, and voice over IP (VoIP). Websites are able to use TLS to secure all communications between their servers and web browsers.

The TLS protocol aims primarily to provide privacy and data integrity between two communicating computer applications. When secured by TLS, connections between a client (e.g., a web browser) and a server (e.g., wikipedia.org) have one or more of the following properties:

* The connection is private (or secure) because symmetric cryptography is used to encrypt the data transmitted. The keys for this symmetric encryption are generated uniquely for each connection and are based on a shared secret negotiated at the start of the session. The server and client negotiate the details of which encryption algorithm and cryptographic keys to use before the first byte of data is transmitted. The negotiation of a shared secret is both secure (the negotiated secret is unavailable to eavesdroppers and cannot be obtained, even by an attacker who places themselves in the middle of the connection) and reliable (no attacker can modify the communications during the negotiation without being detected).
* The identity of the communicating parties can be authenticated using public-key cryptography. This authentication can be made optional, but is generally required for at least one of the parties (typically the server).
* The connection is reliable because each message transmitted includes a message integrity check using a message authentication code to prevent undetected loss or alteration of the data during transmission.

Client-server applications use the TLS protocol to communicate across a network in a way designed to prevent eavesdropping and tampering.

Since applications can communicate either with or without TLS (or SSL), it is necessary for the client to indicate to the server the setup of a TLS connection. One of the main ways of achieving this is to use a different port number for TLS connections, for example port 443 for HTTPS. Another mechanism is for the client to make a protocol-specific request to the server to switch the connection to TLS; for example, by making a STARTTLS request when using the mail and news protocols.

Once the client and server have agreed to use TLS, they negotiate a stateful connection by using a handshaking procedure. The protocols use a handshake with an asymmetric cipher to establish not only cipher settings but also a session-specific shared key with which further communication is encrypted using a symmetric cipher. During this handshake, the client and server agree on various parameters used to establish the connection's security:

* The handshake begins when a client connects to a TLS-enabled server requesting a secure connection and the client presents a list of supported cipher suites (ciphers and hash functions).
* From this list, the server picks a cipher and hash function that it also supports and notifies the client of the decision.
* The server usually then provides identification in the form of a digital certificate. The certificate contains the server name, the trusted certificate authority (CA) that vouches for the authenticity of the certificate, and the server's public encryption key.
* The client confirms the validity of the certificate before proceeding.
* To generate the session keys used for the secure connection, the client either:
    * encrypts a random number with the server's public key and sends the result to the server (which only the server should be able to decrypt with its private key); both parties then use the random number to generate a unique session key for subsequent encryption and decryption of data during the session
    * uses Diffie–Hellman key exchange to securely generate a random and unique session key for encryption and decryption that has the additional property of forward secrecy: if the server's private key is disclosed in future, it cannot be used to decrypt the current session, even if the session is intercepted and recorded by a third party.

This concludes the handshake and begins the secured connection, which is encrypted and decrypted with the session key until the connection closes. If any one of the above steps fails, then the TLS handshake fails and the connection is not created.

**Basic flow**

![TLS](https://github.com/rgederin/security-fundamentals/blob/master/img/TLS.png)

# Public key certificate

In cryptography, a public key certificate, also known as a digital certificate or identity certificate, is an electronic document used to prove the ownership of a public key. The certificate includes information about the key, information about the identity of its owner (called the subject), and the digital signature of an entity that has verified the certificate's contents (called the issuer). If the signature is valid, and the software examining the certificate trusts the issuer, then it can use that key to communicate securely with the certificate's subject. In email encryption, code signing, and e-signature systems, a certificate's subject is typically a person or organization. However, in Transport Layer Security (TLS) a certificate's subject is typically a computer or other device, though TLS certificates may identify organizations or individuals in addition to their core role in identifying devices. TLS, sometimes called by its older name Secure Sockets Layer (SSL), is notable for being a part of HTTPS, a protocol for securely browsing the web.

In a typical public-key infrastructure (PKI) scheme, the certificate issuer is a certificate authority (CA), usually a company that charges customers to issue certificates for them. By contrast, in a web of trust scheme, individuals sign each other's keys directly, in a format that performs a similar function to a public key certificate.

The most common format for public key certificates is defined by X.509. Because X.509 is very general, the format is further constrained by profiles defined for certain use cases, such as Public Key Infrastructure (X.509) as defined in RFC 5280.

## X.509

In cryptography, X.509 is a standard that defines the format of public key certificates. X.509 certificates are used in many Internet protocols, including TLS/SSL, which is the basis for HTTPS[1], the secure protocol for browsing the web. They are also used in offline applications, like electronic signatures. An X.509 certificate contains a public key and an identity (a hostname, or an organization, or an individual), and is either signed by a certificate authority or self-signed. When a certificate is signed by a trusted certificate authority, or validated by other means, someone holding that certificate can rely on the public key it contains to establish secure communications with another party, or validate documents digitally signed by the corresponding private key.

Besides the format for certificates themselves, X.509 specifies certificate revocation lists as a means to distribute information about certificates that are no longer valid, and a certification path validation algorithm, which allows for certificates to be signed by intermediate CA certificates, which are in turn signed by other certificates, eventually reaching a trust anchor.

![x509](https://github.com/rgederin/security-fundamentals/blob/master/img/x509.png)

# Certificate authority

In cryptography, a certificate authority or certification authority (CA) is an entity that issues digital certificates. A digital certificate certifies the ownership of a public key by the named subject of the certificate. This allows others (relying parties) to rely upon signatures or on assertions made about the private key that corresponds to the certified public key. A CA acts as a trusted third party—trusted both by the subject (owner) of the certificate and by the party relying upon the certificate. The format of these certificates is specified by the X.509 standard.

One particularly common use for certificate authorities is to sign certificates used in HTTPS, the secure browsing protocol for the World Wide Web. Another common use is in issuing identity cards by national governments for use in electronically signing documents.

Trusted certificates can be used to create secure connections to a server via the Internet. A certificate is essential in order to circumvent a malicious party which happens to be on the route to a target server which acts as if it were the target. Such a scenario is commonly referred to as a man-in-the-middle attack. The client uses the CA certificate to authenticate the CA signature on the server certificate, as part of the authorizations before launching a secure connection. Usually, client software—for example, browsers—include a set of trusted CA certificates. This makes sense, as many users need to trust their client software. A malicious or compromised client can skip any security check and still fool its users into believing otherwise.

The clients of a CA are server supervisors who call for a certificate that their servers will bestow to users. Commercial CAs charge to issue certificates, and their customers anticipate the CA's certificate to be contained within the majority of web browsers, so that safe connections to the certified servers work efficiently out-of-the-box. The quantity of internet browsers, other devices and applications which trust a particular certificate authority is referred to as ubiquity. Mozilla, which is a non-profit business, issues several commercial CA certificates with its products.[1] While Mozilla developed their own policy, the CA/Browser Forum developed similar guidelines for CA trust. A single CA certificate may be shared among multiple CAs or their resellers. A root CA certificate may be the base to issue multiple intermediate CA certificates with varying validation requirements.

## Issuing a certificate

A CA issues digital certificates that contain a public key and the identity of the owner. The matching private key is not made available publicly, but kept secret by the end user who generated the key pair. The certificate is also a confirmation or validation by the CA that the public key contained in the certificate belongs to the person, organization, server or other entity noted in the certificate. A CA's obligation in such schemes is to verify an applicant's credentials, so that users and relying parties can trust the information in the CA's certificates. CAs use a variety of standards and tests to do so. In essence, the certificate authority is responsible for saying "yes, this person is who they say they are, and we, the CA, certify that".[19]

If the user trusts the CA and can verify the CA's signature, then they can also assume that a certain public key does indeed belong to whoever is identified in the certificate.

![ca](https://github.com/rgederin/security-fundamentals/blob/master/img/ca.png)

# Key terminology

* **Identification** is a statement of who you are. Depending on the situation, this can be a name, email address, account number, etc.

* **Authentication** is the provision of evidence that you are in fact the one **who** was identified (from the word "authentic" - true, genuine).

* **Authorization** is the function of specifying access rights/privileges to resources related to information security and computer security in general and to access control in particular. More formally, "to authorize" is to define an access policy. For example, human resources staff is normally authorized to access employee records and this policy is usually formalized as access control rules in a computer system. During operation, the system uses the access control rules to decide whether access requests from (authentication) shall be approved (granted) or disapproved (rejected).

For example, when you try to get into a private club you will be identified (they will ask your name and surname), authenticate (they will ask to show the passport and check the photo) and authorize (they will check that the name is on the guest list) before they are allowed inside.

Similarly, these terms are used in computer systems where, traditionally, identification is understood to be the receipt of your identity by username or email; under authentication - checking that you know the password from this account, and under authorization - checking your role in the system and the decision to grant access to the requested page or resource.

# Password-based authentication 

This method is based on the fact that the user must provide username and password for successful authentication and authentication in the system. The username / password pair is specified by the user when it is registered in the system, while the username can be the user's email address.

In the case of Web applications, there are several standard protocols for password authentication, which we will discuss below.

## HTTP 

This protocol, described in the HTTP 1.0 / 1.1 standards, has existed for a very long time and is still actively used in the corporate environment. In the case of websites, it works as follows:

* The server, when an unauthorized client accesses a protected resource, sends the HTTP status "401 Unauthorized" and adds the "WWW-Authenticate" header with an indication of the authentication scheme and parameters.

* The browser, when receiving such a response, automatically displays the username and password dialog. The user enters the details of his account.

* In all subsequent requests to this website, the browser automatically adds an HTTP header "Authorization", in which the user's data is sent for authentication by the server.

* The server authenticates the user based on data from this header. The decision to grant access (authorization) is made separately based on the user role, ACL or other account data.

The whole process is standardized and well supported by all browsers and web servers. There are several authentication schemes that differ in terms of security:

It is important that when using HTTP authentication, the user does not have the standard ability to exit the web application, except to close all browser windows.
### Basic

Basic is the simplest scheme, in which the user's username and password are transmitted in the Authorization header in plaintext (base64-encoded). However, when using the HTTPS (HTTP over SSL) protocol, it is relatively secure.

![basic](https://github.com/rgederin/security-fundamentals/blob/master/img/basic.png)

### Digest
Digest access authentication is one of the agreed-upon methods a web server can use to negotiate credentials, such as username or password, with a user's web browser. This can be used to confirm the identity of a user before sending sensitive information, such as online banking transaction history. It applies a hash function to the username and password before sending them over the network. In contrast, basic access authentication uses the easily reversible Base64 encoding instead of encryption, making it non-secure unless used in conjunction with TLS.

Technically, digest authentication is an application of MD5 cryptographic hashing with usage of nonce values to prevent replay attacks. It uses the HTTP protocol.

### NTLM

NTLM is a suite of authentication and session security protocols used in various Microsoft network protocol implementations and supported by the NTLM Security Support Provider ("NTLMSSP"). Originally used for authentication and negotiation of secure DCE/RPC, NTLM is also used throughout Microsoft's systems as an integrated single sign-on mechanism. It is probably best recognized as part of the "Integrated Windows Authentication" stack for HTTP authentication; however, it is also used in Microsoft implementations of SMTP, POP3, IMAP (all part of Exchange), CIFS/SMB, Telnet, SIP, and possibly others.

The NTLM Security Support Provider provides authentication, integrity, and confidentiality services within the Window Security Support Provider Interface (SSPI) framework. SSPI specifies a core set of security functionality that is implemented by supporting providers; the NTLMSSP is such a provider. The SSPI specifies, and the NTLMSSP implements, the following core operations:

* Authentication -- NTLM provides a challenge-response authentication mechanism, in which clients are able to prove their identities without sending a password to the server.
* Signing -- The NTLMSSP provides a means of applying a digital "signature" to a message. This ensures that the signed message has not been modified (either accidentally or intentionally) and that that signing party has knowledge of a shared secret. NTLM implements a symmetric signature scheme (Message Authentication Code, or MAC); that is, a valid signature can only be generated and verified by parties that possess the common shared key.
* Sealing -- The NTLMSSP implements a symmetric-key encryption mechanism, which provides message confidentiality. In the case of NTLM, sealing also implies signing (a signed message is not necessarily sealed, but all sealed messages are signed).

## Forms authentication

For this protocol there is no definite standard, therefore all its implementations are specific for specific systems, or more precisely, for authentication modules of development frameworks.

It works on the following principle: an HTML form is included in the web application, into which the user must enter his username / password and send them to the server via HTTP POST for authentication. If successful, the web application creates a session token, which is usually placed in browser cookies. On subsequent web requests, session token is automatically passed to the server and allows the application to retrieve information about the current user to authorize the request.

![from](https://github.com/rgederin/security-fundamentals/blob/master/img/basic.png)

An application can create a session token in two ways:

* As the identifier of the authenticated user session, which is stored in server memory or in the database. The session should contain all the necessary information about the user in order to be able to authorize his requests.

* As an encrypted and / or signed object containing user data, as well as the validity period. This approach makes it possible to implement the stateless-server architecture, but it requires a mechanism for updating the session token after the expiration. Several standard formats for such tokens are discussed in the section "Authentication by tokens".

It should be understood that intercepting session token often gives a similar level of access as username / password. Therefore, all communications between the client and the server in the case of forms authentication must be performed only over a secure HTTPS connection.

## Other password-based protocols

The two protocols described above are successfully used to authenticate users on websites. But when developing client-server applications using web services (for example, iOS or Android), along with HTTP authentication, non-standard protocols are often used in which data for authentication is transmitted in other parts of the request.

There are only a few places where you can pass username and password in HTTP requests:

* URL query - is considered an unsafe option, because URL strings can be remembered by browsers, proxies and web servers.

* Request body is a secure option, but it is only applicable to queries that contain the message body (such as POST, PUT, PATCH).

* The HTTP header is the optimal version, with the standard Authorization header (for example, with the Basic schema), and other arbitrary headers.

## Common vulnerabilities and implementation errors

Password authentication is considered not a very reliable way, as passwords can often be found, and users tend to use simple and identical passwords in different systems, or write them on scraps of paper. If an attacker could find out the password, the user often does not know about it. In addition, application developers can allow a number of conceptual errors that simplify the hacking of accounts.

Below is a list of the most common vulnerabilities in the case of using password authentication:

* The web application allows users to create simple passwords.
* The web application is not protected against brute-force attacks.
* The Web application itself generates and distributes passwords to users, but does not require changing the password after the first login (ie the current password is somewhere recorded).
* A web application allows the transfer of passwords over an unprotected HTTP connection or in a URL string.
* The web application does not use secure hash functions to store user passwords.
* The web application does not allow users to change the password or not notify users about changing their passwords.
* The Web application uses a vulnerable password recovery feature that can be used to gain unauthorized access to other accounts.
* The web application does not require re-authentication of the user for important actions: changing the password, changing the delivery address of the goods, etc.
* A web application creates session tokens in such a way that they can be matched or predicted for other users.
* A web application allows for passing session tokens over an unprotected HTTP connection, or in a URL string.
* The Web application is vulnerable to session fixation attacks (that is, it does not replace the session token when anonymous user session goes to authenticated).
* The Web application does not set the HttpOnly and Secure flags for browser cookies that contain session tokens.
* The web application does not destroy the user session after a short inactivity period or does not provide a function to exit from the authenticated session.

# Certificate-based Authentication

A certificate is a set of attributes that identify the owner, signed by a certificate authority (CA). CA acts as an intermediary, which guarantees the authenticity of certificates. Also, the certificate is cryptographically associated with the private key, which is stored by the certificate owner and allows you to unambiguously confirm the fact of ownership of the certificate.

On the client side, the certificate along with the private key can be stored in the operating system, in the browser, in a file, on a separate physical device (smart card, USB token). Usually the private key is additionally protected by a password or a PIN.

In web applications, the X.509 standard is traditionally used. Authentication with the X.509 certificate occurs when you connect to the server and is part of the SSL / TLS protocol. This mechanism is also well supported by browsers that allow the user to select and apply a certificate if the website allows such an authentication method.

![certificate](https://github.com/rgederin/security-fundamentals/blob/master/img/certificate.png)

During authentication, the server performs a certificate check based on the following rules:

* The certificate must be signed by a trusted certification authority.
* The certificate must be valid for the current date (validation of the validity period).
* The certificate must not be revoked by the appropriate CA (check exclusion lists).

After successful authentication, the web application can perform query authorization based on certificate data such as subject, issuer, serial number or thumbprint.

The use of certificates for authentication is a much more reliable method than authentication through passwords. This is achieved by creating in the authentication process a digital signature, the presence of which proves the fact of using the private key in a particular situation (non-repudiation). However, the difficulty with the distribution and support of certificates makes this method of authentication inaccessible in wide circles.

# Authentication for one-time passwords

Authentication for one-time passwords is usually applied in addition to password authentication for implementing two-factor authentication (2FA). In this concept, the user needs to provide two types of data to enter the system: something that he knows (for example, a password), and something that he owns (for example, a device for generating one-time passwords). The presence of two factors makes it possible to substantially increase the level of security that m. is claimed for certain types of web applications.

Another popular scenario of using one-time passwords is additional authentication of the user during the execution of important actions: money transfer, change of settings, etc.

There are different sources for creating one-time passwords. Most Popular:

* Hardware or software tokens that can generate one-time passwords based on the secret key entered in them, and the current time. Secret keys of users, which are a factor of ownership, are also stored on the server, which allows you to check the entered one-time passwords. An example of hardware token implementations is RSA SecurID; software - Google Authenticator application.
* Randomly generated codes transmitted to the user via SMS or other communication channel. In this situation, the ownership factor is the user's phone (more precisely, a SIM card tied to a specific number).
* Printout or scratch card with a list of pre-generated one-time passwords. For each new login, you must enter a new one-time password with the specified number.

![device](https://github.com/rgederin/security-fundamentals/blob/master/img/devaice.jpg)

In web applications, this authentication mechanism is often implemented by extending the forms authentication: after initial authentication by the password, a user session is created, however, in the context of this session, the user does not have access to the application until it performs additional authentication over the one-time password.