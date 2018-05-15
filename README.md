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

![basic](https://github.com/rgederin/data-formats/blob/master/img/basic.jpg)

### Digest
Digest access authentication is one of the agreed-upon methods a web server can use to negotiate credentials, such as username or password, with a user's web browser. This can be used to confirm the identity of a user before sending sensitive information, such as online banking transaction history. It applies a hash function to the username and password before sending them over the network. In contrast, basic access authentication uses the easily reversible Base64 encoding instead of encryption, making it non-secure unless used in conjunction with TLS.

Technically, digest authentication is an application of MD5 cryptographic hashing with usage of nonce values to prevent replay attacks. It uses the HTTP protocol.

### NTLM

NTLM is a suite of authentication and session security protocols used in various Microsoft network protocol implementations and supported by the NTLM Security Support Provider ("NTLMSSP"). Originally used for authentication and negotiation of secure DCE/RPC, NTLM is also used throughout Microsoft's systems as an integrated single sign-on mechanism. It is probably best recognized as part of the "Integrated Windows Authentication" stack for HTTP authentication; however, it is also used in Microsoft implementations of SMTP, POP3, IMAP (all part of Exchange), CIFS/SMB, Telnet, SIP, and possibly others.

The NTLM Security Support Provider provides authentication, integrity, and confidentiality services within the Window Security Support Provider Interface (SSPI) framework. SSPI specifies a core set of security functionality that is implemented by supporting providers; the NTLMSSP is such a provider. The SSPI specifies, and the NTLMSSP implements, the following core operations:

* Authentication -- NTLM provides a challenge-response authentication mechanism, in which clients are able to prove their identities without sending a password to the server.
* Signing -- The NTLMSSP provides a means of applying a digital "signature" to a message. This ensures that the signed message has not been modified (either accidentally or intentionally) and that that signing party has knowledge of a shared secret. NTLM implements a symmetric signature scheme (Message Authentication Code, or MAC); that is, a valid signature can only be generated and verified by parties that possess the common shared key.
* Sealing -- The NTLMSSP implements a symmetric-key encryption mechanism, which provides message confidentiality. In the case of NTLM, sealing also implies signing (a signed message is not necessarily sealed, but all sealed messages are signed).

