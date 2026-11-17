/* test_der_chain.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * DER decode / chain verification integration tests against structured
 * malicious input.
 *
 * A leaf certificate is generated locally at run time with wc_MakeCert() /
 * wc_SignCert() and signed by the repository's 2048-bit test CA, so the
 * resulting chain verifies and the extension semantics that were requested
 * when the leaf was built can be checked against what the decoder reports.
 *
 * Copies of that leaf are then put through a *finite, deterministic* set of
 * structural mutations:
 *
 *   - nested DER length fields made inconsistent with their content (one
 *     field at a time, at several depths of the encoding),
 *   - each extension repeated inside the Extensions SEQUENCE (RFC 5280 4.2
 *     forbids a repeated extension),
 *   - the certificate truncated at the tail, which truncates the
 *     signatureValue, and a re-encoded certificate carrying a deliberately
 *     short (well-formed) signatureValue.
 *
 * Every mutant is fed through both layers that this test is about:
 *
 *   1. the ASN.1 decoder, wc_ParseCert(..., NO_VERIFY, ...), and
 *   2. certificate chain verification, wolfSSL_CertManagerVerifyBuffer(),
 *      with the test CA loaded as trust anchor.
 *
 * The central assertion is that the structural mutants are rejected *by the
 * decoder* - the verifier returns the very same decode error - rather than
 * being accepted and only failing later at signature confirmation. The one
 * exception is asserted explicitly: a structurally valid certificate carrying
 * a short signature decodes successfully and is then rejected by the
 * signature check, which is exactly where structural validation legitimately
 * ends.
 *
 * To prove the rejections are not a signature-verification verdict being
 * masked or waived, the certificate manager is fitted with a verify callback
 * that accepts everything. Structural error codes are not overridable, so for
 * those the callback must never be entered (the test counts the calls).
 *
 * The input mutation set is enumerated in the source: no fuzzing loop, no
 * network access, no time-sensitive sampling. Buffers handed to the library
 * are allocated at exactly their logical length, so a build with
 * AddressSanitizer (or any other bounds checker) turns any read past the
 * declared end into a test failure as part of a normal unit test run. Every
 * DecodedCert is released after a failed parse, and the exit-time leak check
 * covers allocations the decoder makes before rejecting the input.
 */

#include <tests/unit.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <tests/api/api.h>
#include <tests/api/test_der_chain.h>

/* The leaf is generated with the certificate-generation API, so that feature,
 * the ASN.1 template parser, and a certificate manager that can create the
 * TLS method its CA loading needs must all be compiled in. */
#if !defined(NO_ASN) && defined(WOLFSSL_ASN_TEMPLATE) && \
    !defined(NO_CERTS) && !defined(NO_RSA) && defined(WOLFSSL_CERT_GEN) && \
    !defined(NO_SHA256) && !defined(NO_ASN_TIME) && !defined(WC_NO_RNG) && \
    !defined(NO_WOLFSSL_CM_VERIFY) && !defined(WOLFSSL_RSA_PUBLIC_ONLY) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH))
    #define TEST_DER_CHAIN
#endif

#ifdef TEST_DER_CHAIN

/* Extension coverage that depends on optional features. */
#ifdef WOLFSSL_CERT_EXT
    #define DERC_HAVE_EXT
#endif
#if defined(WOLFSSL_ALT_NAMES)
    #define DERC_HAVE_SAN
#endif

/* ------------------------------------------------------------------------- */
/* Minimal DER TLV reader, used to locate the fields that get mutated.       */
/* ------------------------------------------------------------------------- */

typedef struct DercTlv {
    byte   tag;
    word32 off;       /* offset of the tag octet                        */
    word32 hdrSz;     /* tag octet plus length octets                   */
    word32 lenOff;    /* offset of the first length octet               */
    word32 lenOctets; /* total octets of the length field               */
    word32 len;       /* content length                                 */
} DercTlv;

#define DERC_MAX_EXTS 16

typedef struct DercLayout {
    DercTlv outer;    /* Certificate SEQUENCE                           */
    DercTlv tbs;      /* tbsCertificate                                */
    DercTlv sigAlg;   /* outer signatureAlgorithm                      */
    DercTlv sigVal;   /* outer signatureValue BIT STRING                */
    DercTlv validity;
    DercTlv subject;
    DercTlv extWrap;  /* [3] EXPLICIT wrapper                           */
    DercTlv extSeq;   /* SEQUENCE OF Extension                          */
    DercTlv exts[DERC_MAX_EXTS];
    int     extCount;
} DercLayout;

/* Read the TLV at "off". Returns 0 when it is well formed and its content
 * lies entirely before "sz". Indefinite lengths and length-of-length wider
 * than four octets are treated as malformed: the certificates under test use
 * DER. */
static int derc_tlv(const byte* p, word32 sz, word32 off, DercTlv* t)
{
    word32 i = off;
    word32 v = 0;
    byte   b;
    byte   n;
    byte   k;

    if (off >= sz)
        return -1;

    t->tag = p[i];
    t->off = off;
    i++;
    if (i >= sz)
        return -1;

    t->lenOff = i;
    b = p[i];
    i++;
    if ((b & 0x80) == 0) {
        t->len = (word32)b;
        t->lenOctets = 1;
    }
    else {
        n = (byte)(b & 0x7f);
        if ((n == 0) || (n > 4))
            return -1;
        if ((word32)n > sz - i)
            return -1;
        for (k = 0; k < n; k++)
            v = (v << 8) | p[i++];
        t->len = v;
        t->lenOctets = (word32)n + 1;
    }

    t->hdrSz = i - off;
    if (t->len > sz - i)
        return -1;

    return 0;
}

/* Octets taken by a DER length field for "len". */
static word32 derc_len_sz(word32 len)
{
    if (len < 0x80)
        return 1;
    if (len <= 0xff)
        return 2;
    return 3;
}

/* Overwrite a length field in place. The caller chooses newLen so that it
 * needs the same number of length octets. */
static void derc_patch_len(byte* p, const DercTlv* t, word32 newLen)
{
    word32 i;
    word32 n = t->lenOctets;

    if (n == 1) {
        p[t->lenOff] = (byte)newLen;
    }
    else {
        p[t->lenOff] = (byte)(0x80 | (n - 1));
        for (i = n - 1; i > 0; i--) {
            p[t->lenOff + i] = (byte)(newLen & 0xff);
            newLen >>= 8;
        }
    }
}

static const byte* derc_content(const byte* p, const DercTlv* t)
{
    return p + t->off + t->hdrSz;
}

/* Locate the fields this suite mutates.
 *
 *   Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
 *                              signatureValue }
 *
 * The TBSCertificate children are walked positionally; the version field is
 * optional per RFC 5280, and the Extensions wrapper is the [3] field.
 * Returns 0 on success. */
static int derc_layout(const byte* p, word32 sz, DercLayout* l)
{
    word32 off;
    word32 end;
    int    i;
    byte   tag;

    XMEMSET(l, 0, sizeof(*l));

    if (derc_tlv(p, sz, 0, &l->outer) != 0)
        return -1;
    if (l->outer.tag != (ASN_SEQUENCE | ASN_CONSTRUCTED))
        return -1;

    off = l->outer.off + l->outer.hdrSz;
    end = off + l->outer.len;

    if (derc_tlv(p, end, off, &l->tbs) != 0 ||
            l->tbs.tag != (ASN_SEQUENCE | ASN_CONSTRUCTED))
        return -1;
    off = l->tbs.off + l->tbs.hdrSz + l->tbs.len;
    if (derc_tlv(p, end, off, &l->sigAlg) != 0 ||
            l->sigAlg.tag != (ASN_SEQUENCE | ASN_CONSTRUCTED))
        return -1;
    off = l->sigAlg.off + l->sigAlg.hdrSz + l->sigAlg.len;
    if (derc_tlv(p, end, off, &l->sigVal) != 0)
        return -1;
    if (l->sigVal.tag != ASN_BIT_STRING)
        return -1;
    if (l->sigVal.off + l->sigVal.hdrSz + l->sigVal.len != end)
        return -1;

    /* TBSCertificate children. */
    off = l->tbs.off + l->tbs.hdrSz;
    end = off + l->tbs.len;
    if (off >= end)
        return -1;

    tag = p[off];
    if ((tag & (byte)~(ASN_CONSTRUCTED | 0x1f)) == ASN_CONTEXT_SPECIFIC) {
        DercTlv ver;                       /* version [0] EXPLICIT, optional */
        if (derc_tlv(p, end, off, &ver) != 0)
            return -1;
        off = ver.off + ver.hdrSz + ver.len;
    }

    for (i = 0; i < 7 && off < end; i++) {
        DercTlv t;

        if (derc_tlv(p, end, off, &t) != 0)
            return -1;

        switch (i) {
            case 0:                        /* serialNumber */
                if (t.tag != ASN_INTEGER)
                    return -1;
                break;
            case 1:                        /* signature AlgorithmIdentifier */
            case 2:                        /* issuer Name */
                if (t.tag != (ASN_SEQUENCE | ASN_CONSTRUCTED))
                    return -1;
                break;
            case 3:                        /* validity */
                if (t.tag != (ASN_SEQUENCE | ASN_CONSTRUCTED))
                    return -1;
                l->validity = t;
                break;
            case 4:                        /* subject Name */
                if (t.tag != (ASN_SEQUENCE | ASN_CONSTRUCTED))
                    return -1;
                l->subject = t;
                break;
            case 5:                        /* subjectPublicKeyInfo */
                if (t.tag != (ASN_SEQUENCE | ASN_CONSTRUCTED))
                    return -1;
                break;
            default:                       /* extensions [3] */
                if (t.tag != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 3))
                    return -1;
                l->extWrap = t;
                break;
        }

        off = t.off + t.hdrSz + t.len;
    }

    if (off != end)
        return -1;
    if (l->extWrap.len == 0)
        return -1;

    /* Extensions ::= SEQUENCE OF Extension; Extension is a SEQUENCE. */
    if (derc_tlv(p, l->extWrap.off + l->extWrap.hdrSz + l->extWrap.len,
            l->extWrap.off + l->extWrap.hdrSz, &l->extSeq) != 0)
        return -1;
    if (l->extSeq.tag != (ASN_SEQUENCE | ASN_CONSTRUCTED))
        return -1;
    if (l->extSeq.off + l->extSeq.hdrSz + l->extSeq.len !=
            l->extWrap.off + l->extWrap.hdrSz + l->extWrap.len)
        return -1;

    off = l->extSeq.off + l->extSeq.hdrSz;
    end = off + l->extSeq.len;
    while (off < end) {
        DercTlv t;

        if (l->extCount >= DERC_MAX_EXTS)
            return -1;
        if (derc_tlv(p, end, off, &t) != 0)
            return -1;
        if (t.tag != (ASN_SEQUENCE | ASN_CONSTRUCTED))
            return -1;
        l->exts[l->extCount++] = t;
        off = t.off + t.hdrSz + t.len;
    }
    if (off != end || l->extCount == 0)
        return -1;

    return 0;
}

/* ------------------------------------------------------------------------- */
/* DER writers used when a value has to be re-encoded.                       */
/* ------------------------------------------------------------------------- */

static word32 derc_put_len(byte* out, word32 len)
{
    if (len < 0x80) {
        out[0] = (byte)len;
        return 1;
    }
    if (len <= 0xff) {
        out[0] = 0x81;
        out[1] = (byte)len;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (byte)(len >> 8);
    out[2] = (byte)len;
    return 3;
}

static word32 derc_put_seq(byte* out, word32 len)
{
    out[0] = (byte)(ASN_SEQUENCE | ASN_CONSTRUCTED);
    return 1 + derc_put_len(out + 1, len);
}

static word32 derc_put_ctx3(byte* out, word32 len)
{
    out[0] = (byte)(ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 3);
    return 1 + derc_put_len(out + 1, len);
}

/* Re-encode the certificate with one extension SEQUENCE copied a second time
 * at the end of the Extensions SEQUENCE. Every enclosing length is recomputed,
 * so the result is valid DER except for the repetition; the signature is
 * carried over unchanged, since the decoder rejects the duplicate before any
 * signature work.
 *
 * extIdx == -1 emits no duplicate and must reproduce the original bytes
 * exactly - that is the self-check of the re-encoder.
 * Returns the new length, or a negative value on error. */
static int derc_dup_ext(const byte* cert, word32 certSz,
    const DercLayout* l, int extIdx, byte* out, word32 outSz)
{
    word32 tbsContentStart;
    word32 prefixSz;
    word32 extSz = 0;
    word32 seqContent;
    word32 seqSz;
    word32 wrapSz;
    word32 tbsContent;
    word32 tbsSz;
    word32 tailOff;
    word32 tailSz;
    word32 outerContent;
    word32 total;
    word32 o;
    const byte* dup = NULL;

    /* The Extensions wrapper must be the last TBSCertificate field. */
    if (l->extWrap.off + l->extWrap.hdrSz + l->extWrap.len !=
            l->tbs.off + l->tbs.hdrSz + l->tbs.len)
        return -1;
    if (l->extSeq.off != l->extWrap.off + l->extWrap.hdrSz)
        return -1;

    if (extIdx >= 0) {
        if (extIdx >= l->extCount)
            return -1;
        dup = cert + l->exts[extIdx].off;
        extSz = l->exts[extIdx].hdrSz + l->exts[extIdx].len;
    }

    tbsContentStart = l->tbs.off + l->tbs.hdrSz;
    prefixSz = l->extWrap.off - tbsContentStart;
    if (prefixSz > l->tbs.len)
        return -1;

    seqContent = l->extSeq.len + extSz;
    seqSz = 1 + derc_len_sz(seqContent) + seqContent;
    wrapSz = 1 + derc_len_sz(seqSz) + seqSz;
    tbsContent = prefixSz + wrapSz;
    tbsSz = 1 + derc_len_sz(tbsContent) + tbsContent;

    tailOff = l->tbs.off + l->tbs.hdrSz + l->tbs.len;
    tailSz = certSz - tailOff;
    outerContent = tbsSz + tailSz;
    total = 1 + derc_len_sz(outerContent) + outerContent;

    if (total > outSz)
        return -1;

    o = 0;
    o += derc_put_seq(out + o, outerContent);
    o += derc_put_seq(out + o, tbsContent);
    XMEMCPY(out + o, cert + tbsContentStart, prefixSz);
    o += prefixSz;
    o += derc_put_ctx3(out + o, seqSz);
    o += derc_put_seq(out + o, seqContent);
    XMEMCPY(out + o, derc_content(cert, &l->extSeq), l->extSeq.len);
    o += l->extSeq.len;
    if (dup != NULL) {
        XMEMCPY(out + o, dup, extSz);
        o += extSz;
    }
    XMEMCPY(out + o, cert + tailOff, tailSz);
    o += tailSz;

    if (o != total)
        return -1;

    return (int)total;
}

/* Re-encode the certificate with the last "cut" octets of the signature BIT
 * STRING content removed and every enclosing length adjusted, so the result is
 * well-formed DER that simply carries a short signature. The TBSCertificate is
 * copied verbatim. */
static int derc_short_sig(const byte* cert, word32 certSz,
    const DercLayout* l, word32 cut, byte* out, word32 outSz)
{
    word32 sigContent;
    word32 sigTlvSz;
    word32 tbsAndAlgSz;
    word32 outerContent;
    word32 total;
    word32 o;

    (void)certSz;

    if ((cut == 0) || (cut >= l->sigVal.len))
        return -1;

    sigContent = l->sigVal.len - cut;
    sigTlvSz = 1 + derc_len_sz(sigContent) + sigContent;

    /* Everything from the first TBSCertificate octet to the signatureValue. */
    tbsAndAlgSz = l->sigVal.off - (l->outer.off + l->outer.hdrSz);
    outerContent = tbsAndAlgSz + sigTlvSz;
    total = 1 + derc_len_sz(outerContent) + outerContent;
    if (total > outSz)
        return -1;

    o = 0;
    o += derc_put_seq(out + o, outerContent);
    XMEMCPY(out + o, cert + l->outer.off + l->outer.hdrSz, tbsAndAlgSz);
    o += tbsAndAlgSz;
    out[o++] = ASN_BIT_STRING;
    o += derc_put_len(out + o, sigContent);
    XMEMCPY(out + o, cert + l->sigVal.off + l->sigVal.hdrSz, sigContent);
    o += sigContent;

    if (o != total)
        return -1;

    return (int)total;
}

/* ------------------------------------------------------------------------- */
/* Feeding mutants to the decoder and to chain verification.                 */
/* ------------------------------------------------------------------------- */

/* Exact-size copy so a read past the logical end is a bounds violation the
 * sanitizer build reports. */
static byte* derc_exact_copy(const byte* der, word32 derSz)
{
    byte* buf = (byte*)XMALLOC(derSz == 0 ? 1 : derSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (buf != NULL && derSz > 0)
        XMEMCPY(buf, der, derSz);
    return buf;
}

/* Decode "der" in isolation. Returns the decode result through *ret, and 0
 * from the helper itself unless memory could not be allocated. */
static int derc_parse_only(const byte* der, word32 derSz, int* ret)
{
    byte* buf;
    DecodedCert cert;

    buf = derc_exact_copy(der, derSz);
    if (buf == NULL)
        return MEMORY_E;

    wc_InitDecodedCert(&cert, buf, derSz, NULL);
    *ret = wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
    wc_FreeDecodedCert(&cert);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}

/* Errors that only mean "the signature did not confirm". Structural mutants
 * must not be diagnosed with these: that would be the fallback the test exists
 * to rule out. */
static int derc_is_sig_only_err(int ret)
{
    return (ret == WC_NO_ERR_TRACE(ASN_SIG_CONFIRM_E)) ||
           (ret == WC_NO_ERR_TRACE(ASN_NO_SIGNER_E)) ||
           (ret == WC_NO_ERR_TRACE(ASN_SELF_SIGNED_E));
}

static int derc_cb_calls = 0;

/* Accepts every certificate. If structural errors were overridable this
 * callback would turn a rejection into WOLFSSL_SUCCESS, so the tests count its
 * invocations and require the count to stay at zero. */
static int derc_accept_all_cb(int ok, WOLFSSL_X509_STORE_CTX* store)
{
    (void)ok;
    (void)store;
    derc_cb_calls++;
    return 1;
}

/* Verify "der" with the test CA loaded and the accepting callback installed.
 * Returns the certificate-manager result. */
static int derc_chain_verify(const byte* der, word32 derSz, int cbCalls)
{
    WOLFSSL_CERT_MANAGER* cm;
    byte* buf;
    int ret;

    cm = wolfSSL_CertManagerNew();
    if (cm == NULL)
        return MEMORY_E;
    /* The repository CA fixture has a fixed validity window; accept it
     * regardless so this suite depends only on the leaf under test. */
    if (wolfSSL_CertManagerLoadCABuffer_ex(cm, ca_cert_der_2048,
            (long)sizeof_ca_cert_der_2048, WOLFSSL_FILETYPE_ASN1, 0,
            WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY) != WOLFSSL_SUCCESS) {
        wolfSSL_CertManagerFree(cm);
        return WOLFSSL_FATAL_ERROR;
    }
    if (cbCalls) {
        derc_cb_calls = 0;
        wolfSSL_CertManagerSetVerify(cm, derc_accept_all_cb);
    }

    buf = derc_exact_copy(der, derSz);
    if (buf == NULL) {
        wolfSSL_CertManagerFree(cm);
        return MEMORY_E;
    }
    ret = wolfSSL_CertManagerVerifyBuffer(cm, buf, (long)derSz,
        WOLFSSL_FILETYPE_ASN1);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wolfSSL_CertManagerFree(cm);

    return ret;
}

/* One structural mutant:
 *   - the decoder must reject it with a structural error,
 *   - the verifier must return that same error,
 *   - the accepting callback must never be consulted.
 *
 * "wantRet" pins the expected decode error when non-zero; otherwise any
 * structural error is accepted (but a signature-only error is not). */
static int derc_check_mutant(const byte* der, word32 derSz, int wantRet)
{
    EXPECT_DECLS;
    int parseRet = 0;
    int cmRet;

    ExpectIntEQ(derc_parse_only(der, derSz, &parseRet), 0);
    ExpectIntLT(parseRet, 0);
    if (wantRet != 0)
        ExpectIntEQ(parseRet, wantRet);
    ExpectFalse(derc_is_sig_only_err(parseRet));

    cmRet = derc_chain_verify(der, derSz, 1);
    ExpectIntLT(cmRet, 0);
    ExpectIntEQ(cmRet, parseRet);
    /* The rejection came from the decoder, so the accepting callback never
     * ran. */
    ExpectIntEQ(derc_cb_calls, 0);

    return EXPECT_RESULT();
}

/* ------------------------------------------------------------------------- */
/* Leaf construction.                                                        */
/* ------------------------------------------------------------------------- */

/* Build the leaf that every mutation starts from. Extensions that depend on
 * optional features are added only when those features are compiled in, so
 * the baseline assertions below stay in step with what can be present. */
static int derc_make_leaf(byte* der, word32 derSz, word32* derLen,
    RsaKey* leafKey, RsaKey* caKey, WC_RNG* rng)
{
    static const byte serial[] = { 0x01, 0x02, 0x03, 0x04,
                                   0x05, 0x06, 0x07, 0x08 };
#ifdef DERC_HAVE_SAN
    /* GeneralNames ::= SEQUENCE { [2] dNSName "example.com" } - the same
     * encoding the certificate generator writes for a DNS SAN. */
    static const byte sanDer[] = {
        0x30, 0x0d,
        0x82, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
    };
#endif
    Cert cert;
    int ret;

    if (wc_InitCert(&cert) != 0)
        return -1;

    cert.sigType = CTC_SHA256wRSA;
    cert.isCA = 0;
    cert.basicConstSet = 1;
    XMEMCPY(cert.serial, serial, sizeof(serial));
    cert.serialSz = (int)sizeof(serial);
    XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.org, "wolfSSL", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.unit, "DER chain", CTC_NAME_SIZE - 1);
    XSTRNCPY(cert.subject.commonName, "der-chain-leaf", CTC_NAME_SIZE - 1);

    /* Issuer comes from the CA certificate; the generator then fills in a
     * validity window around the current time. */
    if (wc_SetIssuerBuffer(&cert, ca_cert_der_2048,
            (int)sizeof_ca_cert_der_2048) != 0)
        ret = -1;
#ifdef DERC_HAVE_EXT
    else if (wc_SetSubjectKeyIdFromPublicKey(&cert, leafKey, NULL) != 0)
        ret = -1;
    else if (wc_SetAuthKeyIdFromCert(&cert, ca_cert_der_2048,
            (int)sizeof_ca_cert_der_2048) != 0)
        ret = -1;
    else if (wc_SetKeyUsage(&cert, "digitalSignature") != 0)
        ret = -1;
    else if (wc_SetExtKeyUsage(&cert, "serverAuth") != 0)
        ret = -1;
    else {
        XSTRNCPY(cert.certPolicies[0], "1.2.3.4", CTC_MAX_CERTPOL_SZ - 1);
        cert.certPoliciesNb = 1;
        ret = 0;
    }
#else
    else
        ret = 0;
#endif
#ifdef DERC_HAVE_SAN
    if (ret == 0) {
        XMEMCPY(cert.altNames, sanDer, sizeof(sanDer));
        cert.altNamesSz = (int)sizeof(sanDer);
    }
#endif

    if (ret == 0) {
        ret = wc_MakeCert(&cert, der, derSz, leafKey, NULL, rng);
        if (ret > 0)
            ret = wc_SignCert(cert.bodySz, cert.sigType, der, derSz,
                caKey, NULL, rng);
        if (ret > 0) {
            *derLen = (word32)ret;
            ret = 0;
        }
        else {
            ret = -1;
        }
    }

    return ret;
}

/* Load the CA private key and the (unrelated) leaf private key. */
static int derc_load_keys(RsaKey* caKey, RsaKey* leafKey)
{
    int ret;
    word32 idx = 0;

    ret = wc_RsaPrivateKeyDecode(ca_key_der_2048, &idx, caKey,
        sizeof_ca_key_der_2048);
    if (ret != 0)
        return ret;
    idx = 0;
    return wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, leafKey,
        sizeof_client_key_der_2048);
}

/* ------------------------------------------------------------------------- */
/* Baseline: the generated chain verifies and extension semantics are kept.  */
/* ------------------------------------------------------------------------- */

static int derc_impl_baseline(void)
{
    EXPECT_DECLS;
    RsaKey caKey;
    RsaKey leafKey;
    WC_RNG rng;
    int caInit = 0;
    int leafInit = 0;
    int rngInit = 0;
    int ret;
    byte* leafDer = NULL;
    word32 leafDerSz = 0;
    DecodedCert caCert;
    DecodedCert leafCert;
    int caDecoded = 0;
    int leafDecoded = 0;

    XMEMSET(&caKey, 0, sizeof(caKey));
    XMEMSET(&leafKey, 0, sizeof(leafKey));
    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngInit = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&caKey, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) caInit = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&leafKey, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) leafInit = 1;
    ExpectIntEQ(derc_load_keys(&caKey, &leafKey), 0);

    ExpectNotNull(leafDer = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (leafDer != NULL) {
        ExpectIntEQ(derc_make_leaf(leafDer, FOURK_BUF, &leafDerSz, &leafKey,
            &caKey, &rng), 0);
        /* A non-trivial, stable encoding is the basis of every mutation. */
        ExpectIntGT((int)leafDerSz, 500);
        ExpectIntLT((int)leafDerSz, (int)FOURK_BUF);
    }

    if (leafDer != NULL && leafDerSz > 0) {
        /* The generated certificate decodes. */
        wc_InitDecodedCert(&leafCert, leafDer, leafDerSz, NULL);
        ret = wc_ParseCert(&leafCert, CERT_TYPE, NO_VERIFY, NULL);
        ExpectIntEQ(ret, 0);
        if (ret == 0) leafDecoded = 1;

        /* The fixture CA decodes and is recognised as a CA. */
        wc_InitDecodedCert(&caCert, ca_cert_der_2048,
            sizeof_ca_cert_der_2048, NULL);
        ret = wc_ParseCert(&caCert, CERT_TYPE, NO_VERIFY, NULL);
        ExpectIntEQ(ret, 0);
        if (ret == 0) caDecoded = 1;
        ExpectIntEQ(caCert.isCA, 1);

        /* Basic constraints: the leaf is not a CA. */
        ExpectIntEQ(leafCert.isCA, 0);
        ExpectIntEQ(leafCert.extBasicConstSet, 1);

#ifdef DERC_HAVE_EXT
        /* Key usage and extended key usage keep the requested values. */
        ExpectIntEQ(leafCert.extKeyUsageSet, 1);
        ExpectIntEQ(leafCert.extKeyUsage, KEYUSE_DIGITAL_SIG);
        ExpectIntEQ(leafCert.extExtKeyUsageSet, 1);
        ExpectIntEQ(leafCert.extExtKeyUsage, EXTKEYUSE_SERVER_AUTH);

        /* Certificate policies survive the decode. */
        ExpectIntEQ(leafCert.extCertPolicySet, 1);

        /* The leaf's authority key identifier names the CA's subject key
         * identifier, so the two certificates chain consistently. */
        ExpectIntEQ(leafCert.extSubjKeyIdSet, 1);
        ExpectIntGT((int)leafCert.extSubjKeyIdSz, 0);
        ExpectIntEQ(leafCert.extAuthKeyIdSet, 1);
        ExpectIntEQ(caCert.extSubjKeyIdSet, 1);
        ExpectIntEQ(leafCert.extAuthKeyIdSz, caCert.extSubjKeyIdSz);
        ExpectIntEQ(XMEMCMP(leafCert.extAuthKeyId, caCert.extSubjKeyId,
            leafCert.extAuthKeyIdSz), 0);
#endif

#ifdef DERC_HAVE_SAN
        /* Subject alternative name: exactly one DNS entry. */
        ExpectIntEQ(leafCert.extSubjAltNameSet, 1);
        ExpectNotNull(leafCert.altNames);
        if (leafCert.altNames != NULL) {
            ExpectIntEQ(leafCert.altNames->type, ASN_DNS_TYPE);
            ExpectIntEQ(leafCert.altNames->len, 11);
            ExpectIntEQ(XMEMCMP(leafCert.altNames->name, "example.com", 11),
                0);
            ExpectNull(leafCert.altNames->next);
        }
#endif

        /* The untouched chain verifies. The manager reports success to the
         * callback (verify_ok non-zero) and the callback accepts it. */
        ExpectIntEQ(derc_chain_verify(leafDer, leafDerSz, 1), WOLFSSL_SUCCESS);
        ExpectIntGE(derc_cb_calls, 1);
    }

    if (leafDecoded) wc_FreeDecodedCert(&leafCert);
    if (caDecoded) wc_FreeDecodedCert(&caCert);
    XFREE(leafDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (leafInit) wc_FreeRsaKey(&leafKey);
    if (caInit) wc_FreeRsaKey(&caKey);
    if (rngInit) wc_FreeRng(&rng);

    return EXPECT_RESULT();
}

/* ------------------------------------------------------------------------- */
/* Nested DER length mutations.                                              */
/* ------------------------------------------------------------------------- */

enum {
    DERC_LEN_OUTER = 0,
    DERC_LEN_TBS,
    DERC_LEN_VALIDITY,
    DERC_LEN_SUBJECT,
    DERC_LEN_EXTWRAP,
    DERC_LEN_EXT0,
    DERC_LEN_SIGVAL
};

typedef struct DercLenCase {
    int target;
    int delta;        /* added to the declared content length */
    int nonStrictOk;  /* tolerated by a WOLFSSL_NO_ASN_STRICT build */
} DercLenCase;

static const DercLenCase derc_len_cases[] = {
    { DERC_LEN_OUTER,    +1, 0 },
    /* A shorter outer SEQUENCE leaves trailing bytes, which a non-strict
     * build is allowed to tolerate. */
    { DERC_LEN_OUTER,    -1, 1 },
    { DERC_LEN_TBS,      +1, 0 },
    { DERC_LEN_TBS,      -1, 0 },
    { DERC_LEN_VALIDITY, +1, 0 },
    { DERC_LEN_VALIDITY, -1, 0 },
    { DERC_LEN_SUBJECT,  +1, 0 },
    { DERC_LEN_SUBJECT,  -1, 0 },
    { DERC_LEN_EXTWRAP,  +1, 0 },
    { DERC_LEN_EXTWRAP,  -1, 0 },
    /* Growing a single Extension's declared length leaves trailing bytes
     * inside the Extensions SEQUENCE, which is tolerated (the SEQUENCE is
     * not over-run); shrinking it makes the following extension octets
     * re-parse as a new - invalid - extension, which is rejected. Only the
     * shrink is therefore a structural rejection. */
    { DERC_LEN_EXT0,     -1, 0 },
    { DERC_LEN_SIGVAL,   +1, 0 },
    { DERC_LEN_SIGVAL,   -1, 0 }
};

/* Apply one length mutation to a writable copy. */
static int derc_apply_len(byte* der, const DercLayout* l, int target, int delta)
{
    const DercTlv* t;

    switch (target) {
        case DERC_LEN_OUTER:    t = &l->outer;    break;
        case DERC_LEN_TBS:      t = &l->tbs;      break;
        case DERC_LEN_VALIDITY: t = &l->validity; break;
        case DERC_LEN_SUBJECT:  t = &l->subject;  break;
        case DERC_LEN_EXTWRAP:  t = &l->extWrap;  break;
        case DERC_LEN_EXT0:     t = &l->exts[0];  break;
        case DERC_LEN_SIGVAL:   t = &l->sigVal;   break;
        default:                return -1;
    }

    /* Keep the length field the same width so only the value changes. */
    if (derc_len_sz((word32)((int)t->len + delta)) != t->lenOctets)
        return -1;

    derc_patch_len(der, t, (word32)((int)t->len + delta));
    return 0;
}

/* A length field nested in the certificate disagrees with the octets it
 * bounds. The decoder must reject it, and chain verification must return the
 * same decoder error rather than reaching - or being rescued by - the
 * signature step. */
static int derc_impl_nested_length_errors(void)
{
    EXPECT_DECLS;
    RsaKey caKey;
    RsaKey leafKey;
    WC_RNG rng;
    int caInit = 0;
    int leafInit = 0;
    int rngInit = 0;
    byte* leafDer = NULL;
    word32 leafDerSz = 0;
    byte* mut = NULL;
    DercLayout layout;
    size_t i;
    int applied;

    XMEMSET(&caKey, 0, sizeof(caKey));
    XMEMSET(&leafKey, 0, sizeof(leafKey));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&layout, 0, sizeof(layout));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngInit = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&caKey, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) caInit = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&leafKey, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) leafInit = 1;
    ExpectIntEQ(derc_load_keys(&caKey, &leafKey), 0);

    ExpectNotNull(leafDer = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(mut = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (leafDer != NULL) {
        ExpectIntEQ(derc_make_leaf(leafDer, FOURK_BUF, &leafDerSz, &leafKey,
            &caKey, &rng), 0);
    }

    if (leafDer != NULL && mut != NULL && leafDerSz > 0) {
        ExpectIntEQ(derc_layout(leafDer, leafDerSz, &layout), 0);
        /* The layout must point at real certificate fields. */
        ExpectIntEQ(layout.outer.tag, (ASN_SEQUENCE | ASN_CONSTRUCTED));
        ExpectIntEQ(layout.tbs.tag, (ASN_SEQUENCE | ASN_CONSTRUCTED));
        ExpectIntEQ(layout.validity.tag, (ASN_SEQUENCE | ASN_CONSTRUCTED));
        ExpectIntEQ(layout.subject.tag, (ASN_SEQUENCE | ASN_CONSTRUCTED));
        ExpectIntEQ(layout.sigVal.tag, ASN_BIT_STRING);
        ExpectIntEQ(layout.extWrap.tag,
            (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 3));
        ExpectIntGT(layout.extCount, 0);

        for (i = 0; i < sizeof(derc_len_cases) / sizeof(derc_len_cases[0]);
                i++) {
#ifdef WOLFSSL_NO_ASN_STRICT
            if (derc_len_cases[i].nonStrictOk)
                continue;
#endif
            XMEMCPY(mut, leafDer, leafDerSz);
            applied = derc_apply_len(mut, &layout, derc_len_cases[i].target,
                derc_len_cases[i].delta);
            ExpectIntEQ(applied, 0);
            if (applied != 0)
                continue;

            /* Structural rejection at the decoder, mirrored by the verifier,
             * with the accepting callback never entered. */
            EXPECT_TEST(derc_check_mutant(mut, leafDerSz, 0));
        }
    }

    XFREE(mut, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(leafDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (leafInit) wc_FreeRsaKey(&leafKey);
    if (caInit) wc_FreeRsaKey(&caKey);
    if (rngInit) wc_FreeRng(&rng);

    return EXPECT_RESULT();
}

/* ------------------------------------------------------------------------- */
/* Duplicate extensions.                                                     */
/* ------------------------------------------------------------------------- */

/* RFC 5280 4.2 makes each extension below non-repeatable. Repeating one that
 * is already in the leaf must be diagnosed by the extension decoder
 * (ASN_OBJECT_ID_E), before any signature work. The re-encoder is validated
 * first by round-tripping the unmodified certificate byte for byte. */
static int derc_impl_duplicate_extensions(void)
{
    EXPECT_DECLS;
    RsaKey caKey;
    RsaKey leafKey;
    WC_RNG rng;
    int caInit = 0;
    int leafInit = 0;
    int rngInit = 0;
    byte* leafDer = NULL;
    word32 leafDerSz = 0;
    byte* rebuilt = NULL;
    byte* mut = NULL;
    DercLayout layout;
    int n;
    int i;

    XMEMSET(&caKey, 0, sizeof(caKey));
    XMEMSET(&leafKey, 0, sizeof(leafKey));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&layout, 0, sizeof(layout));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngInit = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&caKey, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) caInit = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&leafKey, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) leafInit = 1;
    ExpectIntEQ(derc_load_keys(&caKey, &leafKey), 0);

    ExpectNotNull(leafDer = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(rebuilt = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(mut = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (leafDer != NULL) {
        ExpectIntEQ(derc_make_leaf(leafDer, FOURK_BUF, &leafDerSz, &leafKey,
            &caKey, &rng), 0);
    }

    if (leafDer != NULL && rebuilt != NULL && mut != NULL && leafDerSz > 0) {
        ExpectIntEQ(derc_layout(leafDer, leafDerSz, &layout), 0);
        /* The leaf carries basicConstraints at least, plus the extensions
         * that the compiled-in features allow. */
        ExpectIntGT(layout.extCount, 0);

        /* Re-encoder self-check: with no duplicate it reproduces the input
         * exactly, so later failures are caused by the repetition alone. */
        n = derc_dup_ext(leafDer, leafDerSz, &layout, -1, rebuilt, FOURK_BUF);
        ExpectIntEQ(n, (int)leafDerSz);
        if (n == (int)leafDerSz)
            ExpectIntEQ(XMEMCMP(rebuilt, leafDer, leafDerSz), 0);

        for (i = 0; i < layout.extCount; i++) {
            n = derc_dup_ext(leafDer, leafDerSz, &layout, i, mut, FOURK_BUF);
            ExpectIntGT(n, 0);
            if (n <= 0)
                continue;

            /* Well-formed DER, so the only thing wrong with it is the
             * repeated extension; that alone must be the reported error. */
            EXPECT_TEST(derc_check_mutant(mut, (word32)n,
                WC_NO_ERR_TRACE(ASN_OBJECT_ID_E)));
        }
    }

    XFREE(mut, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(rebuilt, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(leafDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (leafInit) wc_FreeRsaKey(&leafKey);
    if (caInit) wc_FreeRsaKey(&caKey);
    if (rngInit) wc_FreeRng(&rng);

    return EXPECT_RESULT();
}

/* ------------------------------------------------------------------------- */
/* Truncated signatures.                                                     */
/* ------------------------------------------------------------------------- */

/* Cutting octets off the tail of the certificate removes part of the
 * signatureValue, and the declared lengths no longer agree with the bytes that
 * are present. Every cut must therefore be a structural decode error, and the
 * verifier must report that same error.
 *
 * A second flavour keeps the DER structurally valid but shortens the
 * signatureValue and fixes up the lengths. That encoding is well formed, so
 * the decoder legitimately accepts it; the chain verifier is the layer that
 * rejects it, at signature confirmation. Asserting both sides pins down where
 * structural validation ends and signature validation begins. */
static int derc_impl_truncated_signature(void)
{
    EXPECT_DECLS;
    static const word32 cuts[] = { 1, 2, 3, 4, 8, 16, 32, 64 };
    static const word32 shortSigs[] = { 1, 16, 64 };
    RsaKey caKey;
    RsaKey leafKey;
    WC_RNG rng;
    int caInit = 0;
    int leafInit = 0;
    int rngInit = 0;
    byte* leafDer = NULL;
    word32 leafDerSz = 0;
    byte* mut = NULL;
    DercLayout layout;
    size_t i;
    int parseRet;
    int cmRet;
    int n;

    XMEMSET(&caKey, 0, sizeof(caKey));
    XMEMSET(&leafKey, 0, sizeof(leafKey));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&layout, 0, sizeof(layout));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngInit = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&caKey, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) caInit = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&leafKey, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) leafInit = 1;
    ExpectIntEQ(derc_load_keys(&caKey, &leafKey), 0);

    ExpectNotNull(leafDer = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(mut = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (leafDer != NULL) {
        ExpectIntEQ(derc_make_leaf(leafDer, FOURK_BUF, &leafDerSz, &leafKey,
            &caKey, &rng), 0);
    }

    if (leafDer != NULL && mut != NULL && leafDerSz > 0) {
        ExpectIntEQ(derc_layout(leafDer, leafDerSz, &layout), 0);
        ExpectIntGT(layout.sigVal.len, 64);

        /* 1. Tail truncation: the signature is cut, and so are the lengths'
         * agreement with the buffer. Structural rejection throughout. */
        for (i = 0; i < sizeof(cuts) / sizeof(cuts[0]); i++) {
            if (cuts[i] >= leafDerSz)
                break;
            EXPECT_TEST(derc_check_mutant(leafDer, leafDerSz - cuts[i], 0));
        }

        /* 2. Short signature, otherwise valid DER: decode succeeds, chain
         * verification fails at the signature check. */
        for (i = 0; i < sizeof(shortSigs) / sizeof(shortSigs[0]); i++) {
            n = derc_short_sig(leafDer, leafDerSz, &layout, shortSigs[i],
                mut, FOURK_BUF);
            ExpectIntGT(n, 0);
            if (n <= 0)
                continue;

            ExpectIntEQ(derc_parse_only(mut, (word32)n, &parseRet), 0);
            /* The structure is intact, so the decoder accepts it... */
            ExpectIntEQ(parseRet, 0);

            /* ...and the chain verifier is what rejects it: with no callback
             * installed, the signature confirmation fails. */
            cmRet = derc_chain_verify(mut, (word32)n, 0);
            ExpectIntLT(cmRet, 0);
#ifndef WOLFSSL_ASYNC_CRYPT
            ExpectIntEQ(cmRet, WC_NO_ERR_TRACE(ASN_SIG_CONFIRM_E));
#endif
        }
    }

    XFREE(mut, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(leafDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (leafInit) wc_FreeRsaKey(&leafKey);
    if (caInit) wc_FreeRsaKey(&caKey);
    if (rngInit) wc_FreeRng(&rng);

    return EXPECT_RESULT();
}

/* ------------------------------------------------------------------------- */
/* Truncation at structural boundaries.                                      */
/* ------------------------------------------------------------------------- */

/* Truncating the certificate at a structural boundary - inside a length field,
 * between two TLVs, at the end of the TBSCertificate, inside the Extensions
 * SEQUENCE, at the end of the signature algorithm - produces inputs whose
 * declared lengths run past the buffer. Each one must be a decode error, not
 * something that reaches signature verification, and the decoder must not read
 * past the short buffer (an exact-size allocation makes an over-read a
 * sanitizer finding).
 *
 * The offsets are enumerated, so the set is finite and repeatable. */
static int derc_impl_boundary_truncation(void)
{
    EXPECT_DECLS;
    RsaKey caKey;
    RsaKey leafKey;
    WC_RNG rng;
    int caInit = 0;
    int leafInit = 0;
    int rngInit = 0;
    byte* leafDer = NULL;
    word32 leafDerSz = 0;
    DercLayout layout;
    word32 offsets[12];
    int count = 0;
    int i;

    XMEMSET(&caKey, 0, sizeof(caKey));
    XMEMSET(&leafKey, 0, sizeof(leafKey));
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&layout, 0, sizeof(layout));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) rngInit = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&caKey, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) caInit = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&leafKey, HEAP_HINT, testDevId), 0);
    if (EXPECT_SUCCESS()) leafInit = 1;
    ExpectIntEQ(derc_load_keys(&caKey, &leafKey), 0);

    ExpectNotNull(leafDer = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    if (leafDer != NULL) {
        ExpectIntEQ(derc_make_leaf(leafDer, FOURK_BUF, &leafDerSz, &leafKey,
            &caKey, &rng), 0);
    }

    if (leafDer != NULL && leafDerSz > 0) {
        ExpectIntEQ(derc_layout(leafDer, leafDerSz, &layout), 0);

#define DERC_MAX_OFFSETS 12
#define DERC_PUSH_OFFSET(v) do { \
    if (count < DERC_MAX_OFFSETS) offsets[count++] = (v); \
    } while (0)

        /* Cut points chosen so each one lands on - or one octet inside - a
         * different structural boundary. */
        DERC_PUSH_OFFSET(layout.outer.hdrSz);         /* inside outer header */
        DERC_PUSH_OFFSET(layout.tbs.off);            /* before the TBS     */
        DERC_PUSH_OFFSET(layout.tbs.off + layout.tbs.hdrSz +
                           (layout.tbs.len / 2));      /* middle of the TBS  */
        DERC_PUSH_OFFSET(layout.tbs.off + layout.tbs.hdrSz +
                           layout.tbs.len);            /* end of the TBS     */
        DERC_PUSH_OFFSET(layout.sigAlg.off +
                           layout.sigAlg.hdrSz);       /* inside sigAlg      */
        DERC_PUSH_OFFSET(layout.sigVal.off + 1);     /* inside sigVal hdr  */
        DERC_PUSH_OFFSET(layout.validity.off +
                           layout.validity.hdrSz);     /* inside validity    */
        DERC_PUSH_OFFSET(layout.subject.off +
                           layout.subject.hdrSz);      /* inside subject     */
        DERC_PUSH_OFFSET(layout.extWrap.off + 1);    /* inside ext wrapper */
        DERC_PUSH_OFFSET(layout.extSeq.off +
                           layout.extSeq.hdrSz);       /* first extension    */
        DERC_PUSH_OFFSET(layout.extSeq.off +
                           layout.extSeq.len / 2);     /* middle of the exts */
        DERC_PUSH_OFFSET(layout.extWrap.off + layout.extWrap.hdrSz +
                           layout.extWrap.len - 1);    /* last ext octet     */

        for (i = 0; i < count; i++) {
            if (offsets[i] == 0 || offsets[i] >= leafDerSz)
                continue;
            EXPECT_TEST(derc_check_mutant(leafDer, offsets[i], 0));
        }

#undef DERC_PUSH_OFFSET
#undef DERC_MAX_OFFSETS
    }

    XFREE(leafDer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (leafInit) wc_FreeRsaKey(&leafKey);
    if (caInit) wc_FreeRsaKey(&caKey);
    if (rngInit) wc_FreeRng(&rng);

    return EXPECT_RESULT();
}

#endif /* TEST_DER_CHAIN */

/* ------------------------------------------------------------------------- */
/* Public entry points.                                                      */
/* ------------------------------------------------------------------------- */

/* Each test returns TEST_SKIPPED when the build does not provide the
 * certificate-generation, ASN.1 template and certificate-manager features the
 * integration exercises need. */
int test_der_chain_baseline(void)
{
    EXPECT_DECLS;
#ifdef TEST_DER_CHAIN
    EXPECT_TEST(derc_impl_baseline());
#endif
    return EXPECT_RESULT();
}

int test_der_chain_nested_length_errors(void)
{
    EXPECT_DECLS;
#ifdef TEST_DER_CHAIN
    EXPECT_TEST(derc_impl_nested_length_errors());
#endif
    return EXPECT_RESULT();
}

int test_der_chain_duplicate_extensions(void)
{
    EXPECT_DECLS;
#ifdef TEST_DER_CHAIN
    EXPECT_TEST(derc_impl_duplicate_extensions());
#endif
    return EXPECT_RESULT();
}

int test_der_chain_truncated_signature(void)
{
    EXPECT_DECLS;
#ifdef TEST_DER_CHAIN
    EXPECT_TEST(derc_impl_truncated_signature());
#endif
    return EXPECT_RESULT();
}

int test_der_chain_boundary_truncation(void)
{
    EXPECT_DECLS;
#ifdef TEST_DER_CHAIN
    EXPECT_TEST(derc_impl_boundary_truncation());
#endif
    return EXPECT_RESULT();
}
