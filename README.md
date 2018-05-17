
- [TLS/SSL](#tlsssl)
- [Public key certificate](#public-key-certificate)
    * [X509](#X509)
- [Certificate authority](#certificate-authority)
    * [Issuing a certificate](#issuing-a-certificate)
- [Encryption](#encryption)
    * [Symmetric-key encryption](#symmetric-key-encryption)
    * [Asymmetric encryption](#asymmetric-encryption)
- [Cryptographic hash function](#cryptographic-hash-function)
    * [Applications](#applications)
- [Key derivation function](#key-derivation-function)
    * [PBKDF2](#pbkdf2)
    * [Salt](#salt)
- [SSO](#sso)
- [CAS](#cas)
- [Multi-factor authentication](#multi-factor-authentication)
- [Encoding vs. Encryption vs. Hashing vs. Obfuscation](#encoding-vs-encryption-vs-hashing-vs-obfuscation)
- [Authentication vs Authorization](#authentication-vs-authorization)
- [Password-based authentication](#password-based-authentication)
    * [HTTP](#http)
    * [Forms authentication](#forms-authentication)
    * [Other password-based protocols](#other-password-based-protocols)
    * [Common vulnerabilities and implementation errors](#common-vulnerabilities-and-implementation-errors)
- [Certificate-based Authentication](#certificate-based-authentication)    
- [Authentication for one-time passwords](#authentication-for-one-time-passwords)   
    
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

The clients of a CA are server supervisors who call for a certificate that their servers will bestow to users. Commercial CAs charge to issue certificates, and their customers anticipate the CA's certificate to be contained within the majority of web browsers, so that safe connections to the certified servers work efficiently out-of-the-box. The quantity of internet browsers, other devices and applications which trust a particular certificate authority is referred to as ubiquity. Mozilla, which is a non-profit business, issues several commercial CA certificates with its products. While Mozilla developed their own policy, the CA/Browser Forum developed similar guidelines for CA trust. A single CA certificate may be shared among multiple CAs or their resellers. A root CA certificate may be the base to issue multiple intermediate CA certificates with varying validation requirements.

## Issuing a certificate

A CA issues digital certificates that contain a public key and the identity of the owner. The matching private key is not made available publicly, but kept secret by the end user who generated the key pair. The certificate is also a confirmation or validation by the CA that the public key contained in the certificate belongs to the person, organization, server or other entity noted in the certificate. A CA's obligation in such schemes is to verify an applicant's credentials, so that users and relying parties can trust the information in the CA's certificates. CAs use a variety of standards and tests to do so. In essence, the certificate authority is responsible for saying "yes, this person is who they say they are, and we, the CA, certify that".[19]

If the user trusts the CA and can verify the CA's signature, then they can also assume that a certain public key does indeed belong to whoever is identified in the certificate.

![ca](https://github.com/rgederin/security-fundamentals/blob/master/img/ca.png)

# Encryption

In cryptography, encryption is the process of encoding a message or information in such a way that only authorized parties can access it and those who are not authorized cannot. Encryption does not itself prevent interference, but denies the intelligible content to a would-be interceptor. In an encryption scheme, the intended information or message, referred to as plaintext, is encrypted using an encryption algorithm – a cipher – generating ciphertext that can be read only if decrypted. For technical reasons, an encryption scheme usually uses a pseudo-random encryption key generated by an algorithm. It is in principle possible to decrypt the message without possessing the key, but, for a well-designed encryption scheme, considerable computational resources and skills are required. An authorized recipient can easily decrypt the message with the key provided by the originator to recipients but not to unauthorized users.

## Symmetric-key encryption

Symmetric-key algorithms are algorithms for cryptography that use the same cryptographic keys for both encryption of plaintext and decryption of ciphertext. The keys may be identical or there may be a simple transformation to go between the two keys. The keys, in practice, represent a shared secret between two or more parties that can be used to maintain a private information link. This requirement that both parties have access to the secret key is one of the main drawbacks of symmetric key encryption, in comparison to public-key encryption (also known as asymmetric key encryption).

Symmetric-key encryption can use either stream ciphers or block ciphers.

* Stream ciphers encrypt the digits (typically bytes), or letters (in substitution ciphers) of a message one at a time. An example is the Vigenere Cipher.
* Block ciphers take a number of bits and encrypt them as a single unit, padding the plaintext so that it is a multiple of the block size. Blocks of 64 bits were commonly used. The Advanced Encryption Standard (AES) algorithm approved by NIST in December 2001, and the GCM block cipher mode of operation use 128-bit blocks.

![symmetric](https://github.com/rgederin/security-fundamentals/blob/master/img/symmetric.png)

## Asymmetric encryption

Public-key cryptography, or asymmetric cryptography, is any cryptographic system that uses pairs of keys: public keys which may be disseminated widely, and private keys which are known only to the owner. This accomplishes two functions: authentication, where the public key verifies that a holder of the paired private key sent the message, and encryption, where only the paired private key holder can decrypt the message encrypted with the public key.

In a public key encryption system, any person can encrypt a message using the receiver's public key. That encrypted message can only be decrypted with the receiver's private key. To be practical, the generation of a public and private key -pair must be computationally economical. The strength of a public key cryptography system relies on the computational effort (work factor in cryptography) required to find the private key from its paired public key. Effective security only requires keeping the private key private; the public key can be openly distributed without compromising security.

Public key cryptography systems often rely on cryptographic algorithms based on mathematical problems that currently admit no efficient solution, particularly those inherent in certain integer factorization, discrete logarithm, and elliptic curve relationships. Public key algorithms, unlike symmetric key algorithms, do not require a secure channel for the initial exchange of one or more secret keys between the parties.

Because of the computational complexity of asymmetric encryption, it is usually used only for small blocks of data, typically the transfer of a symmetric encryption key (e.g. a session key). This symmetric key is then used to encrypt the rest of the potentially long message sequence. The symmetric encryption/decryption is based on simpler algorithms and is much faster.

In a public key signature system, a person can combine a message with a private key to create a short digital signature on the message. Anyone with the corresponding public key can combine a message, a putative digital signature on it, and the known public key to verify whether the signature was valid, i.e. made by the owner of the corresponding private key. Changing the message, even replacing a single letter, will cause verification to fail. In a secure signature system, it is computationally infeasible for anyone who does not know the private key to deduce it from the public key or any number of signatures, or to find a valid signature on any message for which a signature has not hitherto been seen. Thus the authenticity of a message can be demonstrated by the signature, provided the owner of the private key keeps the private key secret.

Public key algorithms are fundamental security ingredients in cryptosystems, applications and protocols. They underpin various Internet standards, such as Transport Layer Security (TLS), S/MIME, PGP, and GPG. Some public key algorithms provide key distribution and secrecy (e.g., Diffie–Hellman key exchange), some provide digital signatures (e.g., Digital Signature Algorithm), and some provide both (e.g., RSA).

Public key cryptography finds application in, among others, the information technology security discipline, information security. Information security (IS) is concerned with all aspects of protecting electronic information assets against security threats. Public key cryptography is used as a method of assuring the confidentiality, authenticity and non-repudiability of electronic communications and data storage.

### Examples

An unpredictable (typically large and random) number is used to begin generation of an acceptable pair of keys suitable for use by an asymmetric key algorithm.

![pkc1](https://github.com/rgederin/security-fundamentals/blob/master/img/pkc1.png)

In an asymmetric key encryption scheme, anyone can encrypt messages using the public key, but only the holder of the paired private key can decrypt. Security depends on the secrecy of the private key.

![pkc2](https://github.com/rgederin/security-fundamentals/blob/master/img/pkc2.png)

In the Diffie–Hellman key exchange scheme, each party generates a public/private key pair and distributes the public key. After obtaining an authentic copy of each other's public keys, Alice and Bob can compute a shared secret offline. The shared secret can be used, for instance, as the key for a symmetric cipher.

![pkc3](https://github.com/rgederin/security-fundamentals/blob/master/img/pkc3.png)

# Cryptographic hash function

A cryptographic hash function is a special class of hash function that has certain properties which make it suitable for use in cryptography. It is a mathematical algorithm that maps data of arbitrary size to a bit string of a fixed size (a hash) and is designed to be a one-way function, that is, a function which is infeasible to invert. The only way to recreate the input data from an ideal cryptographic hash function's output is to attempt a brute-force search of possible inputs to see if they produce a match, or use a rainbow table of matched hashes. Bruce Schneier has called one-way hash functions "the workhorses of modern cryptography". The input data is often called the message, and the output (the hash value or hash) is often called the message digest or simply the digest.

![hash](https://github.com/rgederin/security-fundamentals/blob/master/img/hash.png)

The ideal cryptographic hash function has five main properties:

* it is deterministic so the same message always results in the same hash
* it is quick to compute the hash value for any given message
* it is infeasible to generate a message from its hash value except by trying all possible messages
* a small change to a message should change the hash value so extensively that the new hash value appears uncorrelated with the old hash value
* it is infeasible to find two different messages with the same hash value

Cryptographic hash functions have many information-security applications, notably in digital signatures, message authentication codes (MACs), and other forms of authentication. They can also be used as ordinary hash functions, to index data in hash tables, for fingerprinting, to detect duplicate data or uniquely identify files, and as checksums to detect accidental data corruption. Indeed, in information-security contexts, cryptographic hash values are sometimes called (digital) fingerprints, checksums, or just hash values, even though all these terms stand for more general functions with rather different properties and purposes

## Applications

**Verifying the integrity of files or messages**

An important application of secure hashes is verification of message integrity. Determining whether any changes have been made to a message (or a file), for example, can be accomplished by comparing message digests calculated before, and after, transmission (or any other event).

For this reason, most digital signature algorithms only confirm the authenticity of a hashed digest of the message to be "signed". Verifying the authenticity of a hashed digest of the message is considered proof that the message itself is authentic.

MD5, SHA1, or SHA2 hashes are sometimes posted along with files on websites or forums to allow verification of integrity. This practice establishes a chain of trust so long as the hashes are posted on a site authenticated by HTTPS.

**Password verification**

A related application is password verification (first invented by Roger Needham). Storing all user passwords as cleartext can result in a massive security breach if the password file is compromised. One way to reduce this danger is to only store the hash digest of each password. To authenticate a user, the password presented by the user is hashed and compared with the stored hash. (Note that this approach prevents the original passwords from being retrieved if forgotten or lost, and they have to be replaced with new ones.) The password is often concatenated with a random, non-secret salt value before the hash function is applied. The salt is stored with the password hash. Because users will typically have different salts, it is not feasible to store tables of precomputed hash values for common passwords when salt is employed. On the other hand, standard cryptographic hash functions are designed to be computed quickly, and, as a result, it is possible to try guessed passwords at high rates. Common graphics processing units can try billions of possible passwords each second. Key stretching functions, such as PBKDF2, bcrypt or scrypt, typically use repeated invocations of a cryptographic hash to increase the time, and in some cases computer memory, required to perform brute force attacks on stored password digests.

**File or data identifier**

A message digest can also serve as a means of reliably identifying a file; several source code management systems, including Git, Mercurial and Monotone, use the sha1sum of various types of content (file content, directory trees, ancestry information, etc.) to uniquely identify them. Hashes are used to identify files on peer-to-peer filesharing networks. For example, in an ed2k link, an MD4-variant hash is combined with the file size, providing sufficient information for locating file sources, downloading the file and verifying its contents. Magnet links are another example. Such file hashes are often the top hash of a hash list or a hash tree which allows for additional benefits.

One of the main applications of a hash function is to allow the fast look-up of a data in a hash table. Being hash functions of a particular kind, cryptographic hash functions lend themselves well to this application too.

**Pseudorandom generation and key derivation**

Hash functions can also be used in the generation of pseudorandom bits, or to derive new keys or passwords from a single secure key or password.

# Key derivation function

In cryptography, a key derivation function (KDF) derives one or more secret keys from a secret value such as a master key, a password, or a passphrase using a pseudorandom function. KDFs can be used to stretch keys into longer keys or to obtain keys of a required format, such as converting a group element that is the result of a Diffie–Hellman key exchange into a symmetric key for use with AES. Keyed cryptographic hash functions are popular examples of pseudorandom functions used for key derivation.

## PBKDF2

In cryptography, PBKDF1 and PBKDF2 (Password-Based Key Derivation Function 2) are key derivation functions with a sliding computational cost, aimed to reduce the vulnerability of encrypted keys to brute force attacks.

PBKDF2 is part of RSA Laboratories' Public-Key Cryptography Standards (PKCS) series, specifically PKCS #5 v2.0, also published as Internet Engineering Task Force's RFC 2898. It supersedes PBKDF1, which could only produce derived keys up to 160 bits long. RFC 8018, published in 2017, still recommends PBKDF2 for password hashing, even though newer password hashing functions such as Argon2 are designed to address weaknesses in current function.

PBKDF2 applies a pseudorandom function, such as hash-based message authentication code (HMAC), to the input password or passphrase along with a salt value and repeats the process many times to produce a derived key, which can then be used as a cryptographic key in subsequent operations. The added computational work makes password cracking much more difficult, and is known as key stretching.

Having a salt added to the password reduces the ability to use precomputed hashes (rainbow tables) for attacks, and means that multiple passwords have to be tested individually, not all at once. The standard recommends a salt length of at least 64 bits.

![pbkdf2](https://github.com/rgederin/security-fundamentals/blob/master/img/pbkdf2.png)

## Salt

In cryptography, a salt is random data that is used as an additional input to a one-way function that "hashes" data, a password or passphrase. Salts are closely related to the concept of nonce. The primary function of salts is to defend against dictionary attacks or against its hashed equivalent, a pre-computed rainbow table attack.

Salts are used to safeguard passwords in storage. Historically a password was stored in plaintext on a system, but over time additional safeguards developed to protect a user's password against being read from the system. A salt is one of those methods.

A new salt is randomly generated for each password. In a typical setting, the salt and the password (or its version after Key stretching) are concatenated and processed with a cryptographic hash function, and the resulting output (but not the original password) is stored with the salt in a database. Hashing allows for later authentication without keeping and therefore risking the plaintext password in the event that the authentication data store is compromised.

Since salts do not have to be memorized by humans they can make the size of the rainbow table required for a successful attack prohibitively large without placing a burden on the users. Since salts are different in each case, they also protect commonly used passwords, or those who use the same password on several sites, by making all salted hash instances for the same password different from each other.

Cryptographic salts are broadly used in many modern computer systems, from Unix system credentials to Internet security.

# SSO

Single sign-on (SSO) is a property of access control of multiple related, yet independent, software systems. With this property, a user logs in with a single ID and password to gain access to a connected system or systems without using different usernames or passwords, or in some configurations seamlessly sign on at each system. This is typically accomplished using the Lightweight Directory Access Protocol (LDAP) and stored LDAP databases on (directory) servers.

For clarity, it is best to refer to systems requiring authentication for each application but using the same credentials from a directory server as Directory Server Authentication and systems where a single authentication provides access to multiple applications by passing the authentication token seamlessly to configured applications as Single Sign-On.

Conversely, single sign-off is the property whereby a single action of signing out terminates access to multiple software systems.

As different applications and resources support different authentication mechanisms, single sign-on must internally store the credentials used for initial authentication and translate them to the credentials required for the different mechanisms.

Other shared authentication schemes include OAuth, OpenID, OpenID Connect and Facebook Connect. However, these authentication schemes require the user to enter their login credentials each time they access a different site or application so they are not to be confused with SSO.

![SSO](https://github.com/rgederin/security-fundamentals/blob/master/img/SSO.png)

# CAS

The Central Authentication Service (CAS) is a single sign-on protocol for the web. Its purpose is to permit a user to access multiple applications while providing their credentials (such as userid and password) only once. It also allows web applications to authenticate users without gaining access to a user's security credentials, such as a password. The name CAS also refers to a software package that implements this protocol.

The CAS protocol involves at least three parties: a client web browser, the web application requesting authentication, and the CAS server. It may also involve a back-end service, such as a database server, that does not have its own HTTP interface but communicates with a web application.

When the client visits an application requiring authentication, the application redirects it to CAS. CAS validates the client's authenticity, usually by checking a username and password against a database (such as Kerberos, LDAP or Active Directory).

If the authentication succeeds, CAS returns the client to the application, passing along a service ticket. The application then validates the ticket by contacting CAS over a secure connection and providing its own service identifier and the ticket. CAS then gives the application trusted information about whether a particular user has successfully authenticated.

The **Apereo CAS server** that is the reference implementation of the CAS protocol today supports the following features:

* CAS v1, v2 and v3 Protocol
* SAML v1 and v2 Protocol
* OAuth Protocol
* OpenID & OpenID Connect Protocol
* WS-Federation Passive Requestor Protocol
* Authentication via JAAS, LDAP, RDBMS, X.509, Radius, SPNEGO, JWT, Remote, Trusted, BASIC, Apache Shiro, MongoDB, Pac4J and more.
* Delegated authentication to WS-FED, Facebook, Twitter, SAML IdP, OpenID, OpenID Connect, CAS and more.
* Authorization via ABAC, Time/Date, REST, Internet2's Grouper and more.
* HA clustered deployments via Hazelcast, Ehcache, JPA, Memcached, Apache Ignite, MongoDB, Redis, Couchbase and more.
* Application registration backed by JSON, LDAP, YAML, JPA, Couchbase, MongoDB and more.
* Multifactor authentication via Duo Security, YubiKey, RSA, Google Authenticator and more.
* Administrative UIs to manage logging, monitoring, statistics, configuration, client registration and more.
* Global and per-application user interface theme and branding.
* Password management and password policy enforcement.

# Multi-factor authentication

Multi-factor authentication (MFA) is a method of confirming a user's claimed identity in which a user is granted access only after successfully presenting 2 or more pieces of evidence (or factors) to an authentication mechanism: knowledge (something they and only they know), possession (something they and only they have), and inherence (something they and only they are).

Two-factor authentication (also known as 2FA) is a type (subset) of multi-factor authentication. It is a method of confirming a user's claimed identity by utilizing a combination of two different factors: 1) something they know, 2) something they have, or 3) something they are.

A good example of two-factor authentication is the withdrawing of money from a ATM; only the correct combination of a bank card (something that the user possesses) and a PIN (personal identification number, something that the user knows) allows the transaction to be carried out.

Two-step verification or two-step authentication is a method of confirming a user's claimed identity by utilizing something they know (password) and a second factor other than something they have or something they are. An example of a second step is the user repeating back something that was sent to them through an out-of-band mechanism. Or the second step might be a 6 digit number generated by an app that is common to the user and the authentication system.

# Encoding vs. Encryption vs. Hashing vs. Obfuscation

**Encoding**

The purpose of encoding is to transform data so that it can be properly (and safely) consumed by a different type of system, e.g. binary data being sent over email, or viewing special characters on a web page. The goal is not to keep information secret, but rather to ensure that it’s able to be properly consumed

Examples: ascii, unicode, url encoding, base64

**Encryption**

The purpose of encryption is to transform data in order to keep it secret from others, e.g. sending someone a secret letter that only they should be able to read, or securely sending a password over the Internet. Rather than focusing on usability, the goal is to ensure the data cannot be consumed by anyone other than the intended recipient(s).

Encryption transforms data into another format in such a way that only specific individual(s) can reverse the transformation. It uses a key, which is kept secret, in conjunction with the plaintext and the algorithm, in order to perform the encryption operation. As such, the ciphertext, algorithm, and key are all required to return to the plaintext.

Examples: aes, blowfish, rsa

**Hashing**

Hashing serves the purpose of ensuring integrity, i.e. making it so that if something is changed you can know that it’s changed. Technically, hashing takes arbitrary input and produce a fixed-length string that has the following attributes:

* The same input will always produce the same output.
* Multiple disparate inputs should not produce the same output.
* It should not be possible to go from the output to the input.
* Any modification of a given input should result in drastic change to the hash.
* Hashing is used in conjunction with authentication to produce strong evidence that a given message has not been modified. This is accomplished by taking a given input, hashing it, and then signing the hash with the sender’s private key.

When the recipient opens the message, they can then validate the signature of the hash with the sender’s public key and then hash the message themselves and compare it to the hash that was signed by the sender. If they match it is an unmodified message, sent by the correct person.

Examples: sha-3, md5 (now obsolete), etc.

**Obfuscation**

The purpose of obfuscation is to make something harder to understand, usually for the purposes of making it more difficult to attack or to copy.

One common use is the the obfuscation of source code so that it’s harder to replicate a given product if it is reverse engineered.

It’s important to note that obfuscation is not a strong control (like properly employed encryption) but rather an obstacle. It, like encoding, can often be reversed by using the same technique that obfuscated it. Other times it is simply a manual process that takes time to work through.

Another key thing to realize about obfuscation is that there is a limitation to how obscure the code can become, depending on the content being obscured. If you are obscuring computer code, for example, the limitation is that the result must still be consumable by the computer or else the application will cease to function.

Examples: javascript obfuscator, proguard

**Summary**

* **Encooding** is for maintaining data usability and can be reversed by employing the same algorithm that encoded the content, i.e. no key is used.
* **Encryption** is for maintaining data confidentiality and requires the use of a key (kept secret) in order to return to plaintext.
* **Hashing** is for validating the integrity of content by detecting all modification thereof via obvious changes to the hash output.
* **Obfuscation** is used to prevent people from understanding the meaning of something, and is often used with computer code to help prevent successful reverse engineering and/or theft of a product’s functionality.

# Authentication vs Authorization

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