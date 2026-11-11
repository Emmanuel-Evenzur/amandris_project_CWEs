Source code from the online dating site **amandris.com** which was online from 2008 to 2011.

 ![Web interface](https://github.com/amandris/amandris/blob/master/WebContent/img/screenshot.png)

http://web.archive.org/web/20110207205159/http://amandris.com/ (The internet archive snapshot)

Prerequisites
-------------

* JDK
* Apache Tomcat
* MySql

SAST benchmark
--------------

`JavaSource/com/amandris/clients/web/benchmark` is an intentional weakness suite for benchmarking Mend SAST. Each case is a small servlet mapped under `/benchmark/*` in `WebContent/WEB-INF/web.xml`. The cases are not part of the original 2008–2011 site. Do not deploy this package.

The expected results below come from a Mend CLI code scan of that package only (Mend CLI 26.10.1, Java engine, secrets detection enabled). The legacy application was not part of that scan.

Detected by the Mend CLI
------------------------

| CWE | Mend finding | Severity | Case |
| --- | --- | --- | --- |
| CWE-15 | System Properties Change | Low | `CWE15_SystemPropertyServlet` writes request parameters with `System.setProperty`. `/benchmark/property` |
| CWE-22 | Path/Directory Traversal | High | `CWE22_PathTraversalServlet` opens `C:/amandris/pictures/` plus the `picture` parameter. `/benchmark/file` |
| CWE-78 | Command Injection | High | `CWE78_CommandInjectionServlet` passes `command` to `Runtime.exec`. `/benchmark/command` |
| CWE-79 | Cross-Site Scripting | High | `CWE79_XssServlet` writes `name` into an HTML response. `/benchmark/xss` |
| CWE-89 | SQL Injection | High | `CWE89_SqlInjectionServlet` concatenates `buyerId` into a buyer query. `/benchmark/sql` |
| CWE-90 | LDAP Injection | Medium | `CWE90_LdapInjectionServlet` concatenates `login` into an LDAP filter. `/benchmark/ldap` |
| CWE-94 | Code Injection | High | `CWE94_CodeInjectionServlet` evaluates `expression` with a script engine. `/benchmark/code` |
| CWE-113 | HTTP Header Injection | Low | `CWE113_ResponseSplittingServlet` copies `buyerName` into a response header. `/benchmark/header` |
| CWE-117 | Log Forging | Low | `CWE117_LogInjectionServlet` logs the `comment` parameter. `/benchmark/log` |
| CWE-134 | Unsafe Format String | High | `CWE134_FormatStringServlet` uses `template` as a format string. `/benchmark/format` |
| CWE-319 | Insufficient Transport Layer Protection | Medium | `CWE319_CleartextTransmissionServlet` posts the buyer password to `http://auth.amandris.example/login`. `/benchmark/cleartext-send` |
| CWE-325 | Missing Cryptographic Step | Low | `CWE325_LowIterationPasswordHashServlet` hashes a password with PBKDF2 using one iteration. `/benchmark/password-hash` |
| CWE-327 | Insecure Cryptographic Algorithm | Medium | `CWE327_BrokenCryptoServlet` encrypts a card number with DES. `/benchmark/cipher` |
| CWE-328 | Weak Hash Strength | Low | `CWE328_WeakHashServlet` digests profile text with MD5. `/benchmark/hash` |
| CWE-335 | Predictable Seed | Medium | `CWE335_PredictableSeedServlet` reseeds `SHA1PRNG` with a constant. `/benchmark/seed` |
| CWE-338 | Weak Pseudo-Random | Medium | `CWE338_WeakRandomServlet` builds a reset token with `java.util.Random`. `/benchmark/random` |
| CWE-400 | Regex Denial of Service (ReDoS) | Medium | `CWE400_RegexDosServlet` compiles `pattern` from the request. `/benchmark/regex` |
| CWE-470 | Unsafe Reflection | Medium | `CWE470_UnsafeReflectionServlet` loads `className` from the request. `/benchmark/reflect` |
| CWE-497 | System Properties Disclosure | Low | `CWE497_SystemDataServlet` returns `user.home` and `PATH`. `/benchmark/sysinfo` |
| CWE-501 | Trust Boundary Violation | Medium | `CWE501_TrustBoundaryServlet` stores request `buyerId` in the session. `/benchmark/session` |
| CWE-502 | Deserialization of Untrusted Data | High | `CWE502_DeserializationServlet` deserializes the request body. `/benchmark/deserialize` |
| CWE-601 | Unvalidated/Open Redirect | Low | `CWE601_OpenRedirectServlet` redirects to the `url` parameter. `/benchmark/redirect` |
| CWE-611 | XML External Entity (XXE) Injection | Medium | `CWE611_XxeServlet` parses the request body without disabling external entities. `/benchmark/xml` |
| CWE-643 | XPath Injection | High | `CWE643_XpathInjectionServlet` concatenates `login` into an XPath query. `/benchmark/xpath` |
| CWE-780 | Weak RSA Encryption | Medium | `CWE780_RsaWithoutOaepServlet` encrypts a card number with `RSA/ECB/PKCS1Padding`. `/benchmark/rsa` |
| CWE-798 | Hardcoded Password/Credentials | Medium | `CWE798_HardcodedCredentialsServlet` connects to MySQL with a hard-coded password. `/benchmark/credentials` |
| CWE-918 | Server Side Request Forgery | High | `CWE918_SsrfServlet` fetches the `target` URL. `/benchmark/fetch` |
| CWE-1004 | Cookie Without 'HttpOnly' Flag | Low | `CWE1004_CookieHttpOnlyServlet` sets a session cookie without `HttpOnly`. `/benchmark/cookie` |

The same scan also reports CWE-327 on `CWE325_LowIterationPasswordHashServlet` (`PBKDF2WithHmacSHA1`) and on `CWE780_RsaWithoutOaepServlet` (`RSA/ECB/PKCS1Padding`).

Agentic SAST cases
------------------

These cases are in the suite for agentic SAST. The Mend CLI scan reported CWE-319 and did not report the other four.

| CWE | Case |
| --- | --- |
| CWE-319 | `CWE319_CleartextTransmissionServlet` posts the buyer password to `http://auth.amandris.example/login`. `/benchmark/cleartext-send` |
| CWE-312 | `CWE312_CleartextStorageServlet` saves the buyer password in a `password` column and appends the card number to a text file. `/benchmark/cleartext-storage` |
| CWE-306 | `CWE306_MissingAuthenticationServlet` deletes a buyer account from `buyerId` and does not read the session. `/benchmark/delete-account` |
| CWE-639 | `CWE639_IdorMessageServlet` requires a logged-in buyer, then returns the private message selected by `messageId` without comparing that message's owner to the session buyer. `/benchmark/message` |
| CWE-862 | `CWE862_MissingAuthorizationServlet` requires a logged-in buyer, then deletes every buyer account. The session `role` is passed through and never compared to `admin`. `/benchmark/admin/delete-buyers` |
