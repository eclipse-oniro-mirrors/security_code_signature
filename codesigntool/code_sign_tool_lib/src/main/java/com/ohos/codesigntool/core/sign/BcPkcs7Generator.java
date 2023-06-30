/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ohos.codesigntool.core.sign;

import com.ohos.codesigntool.core.config.CodeSignerConfig;
import com.ohos.codesigntool.core.exception.SignatureException;
import com.ohos.codesigntool.core.utils.Pair;
import com.ohos.codesigntool.core.verify.VerifyUtils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.asn1.pkcs.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;
import java.util.List;

/**
 * BC implementation
 *
 * @since 2023/06/05
 */
public class BcPkcs7Generator implements Pkcs7Generator {
    private static final Logger LOGGER = LogManager.getLogger(BcPkcs7Generator.class);
    private static final SignatureAlgorithmIdentifierFinder SIGN_ALG_FINDER =
        new DefaultSignatureAlgorithmIdentifierFinder();
    private static final DigestAlgorithmIdentifierFinder DIGEST_ALG_FINDER =
        new DefaultDigestAlgorithmIdentifierFinder();

    private static final String SIGNATURE_VERIFY_FAILED = "Signature did not verify";

    @Override
    public byte[] generateSignedData(byte[] content, CodeSignerConfig signerConfig) throws SignatureException {
        if (content == null) {
            throw new SignatureException("unsigned data is null");
        }
        ASN1EncodableVector signerInfoLst = new ASN1EncodableVector();
        ASN1EncodableVector algorithmIdLst = new ASN1EncodableVector();
        for (SignatureAlgorithm signatureAlgorithm : signerConfig.getSignatureAlgorithms()) {
            try {
                SignerInfo signerInfo = getSignerInfo(signatureAlgorithm, content, signerConfig);
                if (signerInfo != null) {
                    algorithmIdLst.add(signerInfo.getDigestAlgorithm());
                    signerInfoLst.add(signerInfo);
                }
                LOGGER.info("Add sign data in sign info list success.");
            } catch (NoSuchAlgorithmException e) {
                throw new SignatureException(
                        "Invalid algorithm: " + signatureAlgorithm.getContentDigestAlgorithm().name(), e);
            } catch (IOException e) {
                throw new SignatureException("sign IOException" + e.getMessage(), e);
            }
        }
        return packagePKCS7(signerConfig, new DERSet(signerInfoLst), new DERSet(algorithmIdLst), content);
    }

    private byte[] packagePKCS7(
            CodeSignerConfig signerConfig,
            ASN1Set signerInfoLst,
            ASN1Set algorithmIdLst,
            byte[] unsignedHapDigest)
            throws SignatureException {
        // must be null, otherwise kernel will return BADMSG err
        ContentInfo contentInfo = new ContentInfo(PKCSObjectIdentifiers.data, null);
        ASN1Set certs = null;
        ASN1Set crls = null;
        byte[] signResult;
        try {
            if (checkListNotNullOrEmty(signerConfig.getCertificates())) {
                certs = createBerSetFromCerts(signerConfig.getCertificates());
            }
            if (checkListNotNullOrEmty(signerConfig.getX509CRLs())) {
                crls = createBerSetFromCrls(signerConfig.getX509CRLs());
            }
            SignedData signedData = new SignedData(
                new ASN1Integer(1), algorithmIdLst, contentInfo, certs, crls, signerInfoLst);
            ContentInfo pkcs7 = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);
            signResult = pkcs7.getEncoded(ASN1Encoding.DER);
        } catch (CertificateEncodingException | CRLException | IOException e) {
            throw new SignatureException("Packaging PKCS cms data failed!", e);
        }

        boolean verifyResult = false;
        try {
            verifyResult = VerifyUtils.verifyPKCS7withContent(unsignedHapDigest, signResult);
        } catch (CMSException e) {
            throw new SignatureException("PKCS cms data verify failed", e);
        }
        if (!verifyResult) {
            throw new SignatureException("PKCS cms data did not verify");
        }
        return signResult;
    }

    private SignerInfo getSignerInfo(
            SignatureAlgorithm signatureAlgorithm, byte[] unsignedHapDigest, CodeSignerConfig signerConfig)
            throws SignatureException, IOException, NoSuchAlgorithmException {
        Pair<String, ? extends AlgorithmParameterSpec> signatureParams = signatureAlgorithm.getSignatureAlgAndParams();
        ContentDigestAlgorithm contentDigestAlg = signatureAlgorithm.getContentDigestAlgorithm();
        String jcaSignatureAlg = signatureParams.getFirst();
        MessageDigest md = MessageDigest.getInstance(contentDigestAlg.name());
        byte[] digest = md.digest(unsignedHapDigest);
        ASN1Set authed = generatePKCS9Attributes(digest);

        // Get sign data content from sign server
        byte[] signatureBytes = signerConfig.getSignature(
            authed.getEncoded(), jcaSignatureAlg, signatureParams.getSecond());
        if (signatureBytes == null) {
            throw new SignatureException("Generate signature bytes error");
        }
        if (signerConfig.getCertificates().isEmpty()) {
            throw new SignatureException("No certificates configured for signer");
        }

        Pair<String, ? extends AlgorithmParameterSpec> obj = signatureAlgorithm.getSignatureAlgAndParams();
        Pair<String, AlgorithmParameterSpec> signAlgPair = Pair.create(obj.getFirst(), obj.getSecond());
        if (!verifySignatureFromServer(signerConfig, signatureBytes, signAlgPair, authed.getEncoded())) {
            throw new SignatureException(SIGNATURE_VERIFY_FAILED);
        }
        return createSignerInfo(signerConfig, signatureAlgorithm, authed, signatureBytes);
    }

    private SignerInfo createSignerInfo(
            CodeSignerConfig signerConfig,
            SignatureAlgorithm signatureAlgorithm,
            ASN1Set authed,
            byte[] signedHapDigest)
            throws SignatureException {
        String digestAlgorithm = signatureAlgorithm.getContentDigestAlgorithm().getDigestAlgorithm();
        String signAlg = signatureAlgorithm.getSignatureAlgAndParams().getFirst();
        try {
            JcaX509CertificateHolder certificateHolder =
                new JcaX509CertificateHolder(signerConfig.getCertificates().get(0));
            AlgorithmIdentifier digestAlgId = DIGEST_ALG_FINDER.find(digestAlgorithm);
            AlgorithmIdentifier signAlgId = SIGN_ALG_FINDER.find(signAlg);
            IssuerAndSerialNumber issuerAndSerialNumber =
                new IssuerAndSerialNumber(certificateHolder.getIssuer(), certificateHolder.getSerialNumber());
            return new SignerInfo(new ASN1Integer(1), issuerAndSerialNumber, digestAlgId,
                    authed, signAlgId, new DEROctetString(signedHapDigest), null);
        } catch (CertificateEncodingException e) {
            throw new SignatureException("Generate signer info error", e);
        }
    }

    private ASN1Set generatePKCS9Attributes(byte[] digest) {
        ASN1EncodableVector table = new ASN1EncodableVector();
        Attribute signTime = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_signingTime,
            new DERSet(new Time(new Date())));
        Attribute contentType = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_contentType,
            new DERSet(PKCSObjectIdentifiers.data));
        Attribute digestAtt = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest,
            new DERSet(new DEROctetString(digest)));
            table.add(signTime);
            table.add(contentType);
            table.add(digestAtt);
            return new DERSet(table);
    }

    private ASN1Set createBerSetFromCrls(List<X509CRL> crls) throws CRLException {
        if (crls == null || crls.size() == 0) {
            return null;
        }
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (X509CRL crl : crls) {
            vector.add(new JcaX509CRLHolder(crl).toASN1Structure());
        }
        return new BERSet(vector);
    }

    private ASN1Set createBerSetFromCerts(List<X509Certificate> certs) throws CertificateEncodingException {
        if (certs == null || certs.size() == 0) {
            return null;
        }
        ASN1EncodableVector vector = new ASN1EncodableVector();

        for (X509Certificate cert : certs) {
            vector.add(new JcaX509CertificateHolder(cert).toASN1Structure());
        }
        return new BERSet(vector);
    }

    private boolean checkListNotNullOrEmty(List<?> lists) {
        return (lists != null) && (lists.size() > 0);
    }

    private boolean verifySignatureFromServer(
            CodeSignerConfig signerConfig,
            byte[] signatureBytes,
            Pair<String, AlgorithmParameterSpec> signAlgPair,
            byte[] authed)
            throws SignatureException {
        try {
            PublicKey publicKey = signerConfig.getCertificates().get(0).getPublicKey();
            Signature signature = Signature.getInstance(signAlgPair.getFirst());
            signature.initVerify(publicKey);
            if (signAlgPair.getSecond() != null) {
                signature.setParameter(signAlgPair.getSecond());
            }
            signature.update(authed);
            if (signatureBytes == null) {
                LOGGER.error("signatureBytes is null");
                throw new SignatureException(SIGNATURE_VERIFY_FAILED);
            }
            if (!signature.verify(signatureBytes)) {
                throw new SignatureException(SIGNATURE_VERIFY_FAILED);
            }
            return true;
        } catch (InvalidKeyException | java.security.SignatureException e) {
            LOGGER.error("Failed to verify generated signature using public key from certificate", e);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Failed to verify generated " + signAlgPair.getFirst()
                    + " signature using public key from certificate", e);
        } catch (InvalidAlgorithmParameterException e) {
            LOGGER.error("Failed to verify generated " + signAlgPair.getSecond()
                    + " signature using public key from certificate", e);
        }
        return false;
    }
}
