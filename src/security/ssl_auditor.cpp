#include "security/ssl_auditor.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace
{

std::string certificateName(
    X509* certificate,
    bool issuer
)
{
    if (!certificate)
    {
        return {};
    }

    X509_NAME* name =
        issuer
            ? X509_get_issuer_name(certificate)
            : X509_get_subject_name(certificate);

    if (!name)
    {
        return {};
    }

    BIO* bio =
        BIO_new(BIO_s_mem());

    if (!bio)
    {
        return {};
    }

    if (
        X509_NAME_print_ex(
            bio,
            name,
            0,
            XN_FLAG_RFC2253
        ) < 0
    )
    {
        BIO_free(bio);
        return {};
    }

    char* data = nullptr;

    long length =
        BIO_get_mem_data(
            bio,
            &data
        );

    std::string result;

    if (length > 0 && data)
    {
        result.assign(
            data,
            static_cast<std::size_t>(length)
        );
    }

    BIO_free(bio);

    return result;
}


std::string asn1TimeToString(
    const ASN1_TIME* time
)
{
    if (!time)
    {
        return {};
    }

    BIO* bio =
        BIO_new(BIO_s_mem());

    if (!bio)
    {
        return {};
    }

    if (
        ASN1_TIME_print(
            bio,
            time
        ) != 1
    )
    {
        BIO_free(bio);
        return {};
    }

    char* data = nullptr;

    long length =
        BIO_get_mem_data(
            bio,
            &data
        );

    std::string result;

    if (length > 0 && data)
    {
        result.assign(
            data,
            static_cast<std::size_t>(length)
        );
    }

    BIO_free(bio);

    return result;
}


bool certificateTimeExpired(
    X509* certificate
)
{
    if (!certificate)
    {
        return true;
    }

    const ASN1_TIME* notBefore =
        X509_get0_notBefore(certificate);

    const ASN1_TIME* notAfter =
        X509_get0_notAfter(certificate);

    if (!notBefore || !notAfter)
    {
        return true;
    }

    if (
        X509_cmp_current_time(notBefore) > 0
    )
    {
        return true;
    }

    if (
        X509_cmp_current_time(notAfter) < 0
    )
    {
        return true;
    }

    return false;
}


bool certificateIsExpired(
    X509* certificate
)
{
    if (!certificate)
    {
        return true;
    }

    const ASN1_TIME* notAfter =
        X509_get0_notAfter(certificate);

    if (!notAfter)
    {
        return true;
    }

    return X509_cmp_current_time(notAfter) < 0;
}


bool certificateIsSelfSigned(
    X509* certificate
)
{
    if (!certificate)
    {
        return false;
    }

    return X509_NAME_cmp(
        X509_get_subject_name(certificate),
        X509_get_issuer_name(certificate)
    ) == 0;
}

} // namespace


SSLFinding SSLAuditor::makeFinding(
    SSLSeverity severity,
    const std::string& id,
    const std::string& title,
    const std::string& description,
    const std::string& evidence,
    const std::string& remediation,
    int confidence
)
{
    SSLFinding finding;

    finding.severity = severity;

    finding.id = id;
    finding.title = title;
    finding.description = description;
    finding.evidence = evidence;
    finding.remediation = remediation;

    finding.confidence =
        std::max(
            0,
            std::min(
                100,
                confidence
            )
        );

    return finding;
}


SSLAuditResult SSLAuditor::audit(
    const std::string& host,
    int port
) const
{
    SSLAuditResult result;

    result.host = host;
    result.port = port;

    /*
     * OpenSSL initialization.
     *
     * Modern OpenSSL initializes the required
     * algorithms automatically, but creating the
     * SSL context remains necessary.
     */

    SSL_CTX* context =
        SSL_CTX_new(
            TLS_client_method()
        );

    if (!context)
    {
        result.findings.push_back(
            makeFinding(
                SSLSeverity::HIGH,
                "SLP-SSL-CONTEXT",
                "Unable to initialize TLS context",
                "SlipNet could not initialize the OpenSSL "
                "TLS client context.",
                "SSL_CTX_new() failed.",
                "Verify the OpenSSL installation and runtime "
                "configuration.",
                100
            )
        );

        return result;
    }

    /*
     * We deliberately do not disable certificate
     * verification globally.
     *
     * Verification is enabled so that SlipNet can
     * identify certificate trust problems.
     */

    SSL_CTX_set_verify(
        context,
        SSL_VERIFY_PEER,
        nullptr
    );

    SSL_CTX_set_default_verify_paths(
        context
    );

    SSL* ssl = nullptr;
    BIO* bio = nullptr;

    const std::string target =
        host + ":" + std::to_string(port);

    bio =
        BIO_new_connect(
            target.c_str()
        );

    if (!bio)
    {
        SSL_CTX_free(context);
        return result;
    }

    /*
     * TCP connection timeout.
     *
     * BIO_connect uses the underlying OpenSSL
     * networking abstraction, keeping this code
     * portable across Linux and Windows.
     */

    BIO_set_conn_hostname(
        bio,
        target.c_str()
    );

    if (
        BIO_do_connect(bio) <= 0
    )
    {
        BIO_free_all(bio);
        SSL_CTX_free(context);

        result.findings.push_back(
            makeFinding(
                SSLSeverity::INFO,
                "SLP-SSL-NOCONNECT",
                "TLS endpoint unreachable",
                "SlipNet could not establish the underlying "
                "TCP connection to the TLS service.",
                target,
                "Verify that the host is reachable and that "
                "the specified port provides a TLS service.",
                100
            )
        );

        return result;
    }

    result.connected = true;

    ssl =
        SSL_new(context);

    if (!ssl)
    {
        BIO_free_all(bio);
        SSL_CTX_free(context);
        return result;
    }

    /*
     * Attach the connected BIO to OpenSSL.
     */
    SSL_set_bio(
        ssl,
        bio,
        bio
    );

    /*
     * Enable hostname verification when the target
     * looks like a DNS hostname.
     *
     * For raw IP addresses, OpenSSL certificate
     * verification is still performed, but hostname
     * matching is only meaningful when the certificate
     * contains an appropriate IP SAN.
     */

    X509_VERIFY_PARAM* param =
        SSL_get0_param(ssl);

    if (param)
    {
        X509_VERIFY_PARAM_set1_host(
            param,
            host.c_str(),
            0
        );
    }

    if (
        SSL_connect(ssl) != 1
    )
    {
        result.findings.push_back(
            makeFinding(
                SSLSeverity::MEDIUM,
                "SLP-TLS-HANDSHAKE",
                "TLS handshake failed",
                "The TCP service accepted a connection but "
                "did not complete a TLS handshake.",
                target,
                "Verify that the service actually speaks TLS "
                "and supports a compatible protocol version.",
                100
            )
        );

        SSL_free(ssl);
        SSL_CTX_free(context);

        return result;
    }

    result.tlsEstablished = true;

    const char* version =
        SSL_get_version(ssl);

    if (version)
    {
        result.tlsVersion =
            version;
    }

    const SSL_CIPHER* selectedCipher =
        SSL_get_current_cipher(ssl);

    if (selectedCipher)
    {
        const char* cipherName =
            SSL_CIPHER_get_name(
                selectedCipher
            );

        if (cipherName)
        {
            result.cipher =
                cipherName;
        }
    }

    X509* certificate =
        SSL_get_peer_certificate(ssl);

    if (!certificate)
    {
        result.findings.push_back(
            makeFinding(
                SSLSeverity::HIGH,
                "SLP-TLS-NOCERT",
                "TLS service did not provide a certificate",
                "The TLS handshake completed without a peer "
                "certificate.",
                target,
                "Configure the TLS service with a valid server "
                "certificate.",
                100
            )
        );
    }
    else
    {
        result.subject =
            certificateName(
                certificate,
                false
            );

        result.issuer =
            certificateName(
                certificate,
                true
            );

        result.validFrom =
            asn1TimeToString(
                X509_get0_notBefore(
                    certificate
                )
            );

        result.validUntil =
            asn1TimeToString(
                X509_get0_notAfter(
                    certificate
                )
            );

        result.certificateExpired =
            certificateIsExpired(
                certificate
            );

        result.certificateValid =
            !certificateTimeExpired(
                certificate
            );

        result.selfSigned =
            certificateIsSelfSigned(
                certificate
            );

        if (result.certificateExpired)
        {
            result.findings.push_back(
                makeFinding(
                    SSLSeverity::HIGH,
                    "SLP-SSL-EXPIRED",
                    "Expired TLS certificate",
                    "The server certificate is no longer valid.",
                    "Certificate expiry: " +
                        result.validUntil,
                    "Replace the certificate with a currently "
                    "valid certificate.",
                    100
                )
            );
        }

        if (result.selfSigned)
        {
            result.findings.push_back(
                makeFinding(
                    SSLSeverity::MEDIUM,
                    "SLP-SSL-SELFSIGNED",
                    "Self-signed TLS certificate",
                    "The server certificate is self-signed and "
                    "may not be trusted by standard clients.",
                    "Subject and issuer are identical.",
                    "Use a certificate issued by a trusted "
                    "certificate authority when appropriate.",
                    100
                )
            );
        }

        X509_free(certificate);
    }

    /*
     * TLS version assessment.
     */

    if (
        result.tlsVersion == "TLSv1" ||
        result.tlsVersion == "TLSv1.1"
    )
    {
        result.findings.push_back(
            makeFinding(
                SSLSeverity::HIGH,
                "SLP-WEAK-TLS-VERSION",
                "Legacy TLS protocol negotiated",
                "The server negotiated a legacy TLS protocol "
                "version that should generally no longer be used.",
                result.tlsVersion,
                "Disable legacy TLS protocols and require "
                "TLS 1.2 or newer.",
                100
            )
        );
    }
    else if (
        result.tlsVersion == "TLSv1.2"
    )
    {
        result.findings.push_back(
            makeFinding(
                SSLSeverity::INFO,
                "SLP-TLS12",
                "TLS 1.2 negotiated",
                "The service successfully negotiated TLS 1.2.",
                result.tlsVersion,
                "Prefer TLS 1.3 where supported while maintaining "
                "compatibility requirements.",
                100
            )
        );
    }

    /*
     * Cipher assessment.
     */

    if (
        result.cipher.find("RC4") != std::string::npos ||
        result.cipher.find("3DES") != std::string::npos ||
        result.cipher.find("DES") != std::string::npos ||
        result.cipher.find("NULL") != std::string::npos ||
        result.cipher.find("EXPORT") != std::string::npos
    )
    {
        result.findings.push_back(
            makeFinding(
                SSLSeverity::HIGH,
                "SLP-WEAK-CIPHER",
                "Weak TLS cipher negotiated",
                "The negotiated TLS cipher indicates a legacy "
                "or weak cryptographic configuration.",
                result.cipher,
                "Disable weak cipher suites and use modern "
                "AEAD-based cipher suites.",
                98
            )
        );
    }

    /*
     * Certificate verification.
     */

    long verifyResult =
        SSL_get_verify_result(
            ssl
        );

    if (
        verifyResult != X509_V_OK
    )
    {
        result.findings.push_back(
            makeFinding(
                SSLSeverity::HIGH,
                "SLP-CERT-VERIFY",
                "Certificate trust verification failed",
                "OpenSSL could not establish a trusted "
                "certificate chain for the TLS service.",
                X509_verify_cert_error_string(
                    verifyResult
                ),
                "Install a certificate issued by a trusted "
                "certificate authority and provide the correct "
                "certificate chain.",
                100
            )
        );
    }

    /*
     * TLS 1.3 is the preferred modern protocol.
     */
    if (
        result.tlsVersion == "TLSv1.3"
    )
    {
        result.findings.push_back(
            makeFinding(
                SSLSeverity::INFO,
                "SLP-TLS13",
                "Modern TLS protocol negotiated",
                "The service successfully negotiated TLS 1.3.",
                result.tlsVersion,
                "Continue maintaining current TLS configuration "
                "and monitor future cryptographic recommendations.",
                100
            )
        );
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);

    SSL_CTX_free(context);

    return result;
}


std::string SSLAuditor::nameFromCertificate(
    void* certificate,
    bool issuer
)
{
    return certificateName(
        static_cast<X509*>(certificate),
        issuer
    );
}


std::string SSLAuditor::certificateTime(
    void* certificate,
    bool notBefore
)
{
    X509* cert =
        static_cast<X509*>(certificate);

    if (!cert)
    {
        return {};
    }

    return asn1TimeToString(
        notBefore
            ? X509_get0_notBefore(cert)
            : X509_get0_notAfter(cert)
    );
}