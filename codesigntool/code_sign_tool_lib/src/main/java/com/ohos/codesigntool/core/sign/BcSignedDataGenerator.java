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

import com.ohos.codesigntool.core.config.CodeSignConfig;
import com.ohos.codesigntool.core.exception.CodeSignException;
import com.ohos.codesigntool.core.utils.CmsUtils;
import com.ohos.codesigntool.core.utils.DigestUtils;
import com.ohos.codesigntool.core.utils.Pair;

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
public class BcSignedDataGenerator implements SignedDataGenerator {
    private static final Logger LOGGER = LogManager.getLogger(BcSignedDataGenerator.class);
    private static final SignatureAlgorithmIdentifierFinder SIGN_ALG_ID_FINDER =
        new DefaultSignatureAlgorithmIdentifierFinder();
    private static final DigestAlgorithmIdentifierFinder DIGEST_ALG_ID_FINDER =
        new DefaultDigestAlgorithmIdentifierFinder();

    @Override
    public byte[] generateSignedData(byte[] content, CodeSignConfig signConfig)
            throws CodeSignException {
        if (content == null) {
            throw new CodeSignException("Verity digest is null");
        }
        Pair<DERSet, DERSet> pairDigestAndSignInfo = getSignInfo(content, signConfig);
        SignedData signedData = new SignedData(
            new ASN1Integer(1),
            pairDigestAndSignInfo.getKey(),
            new ContentInfo(PKCSObjectIdentifiers.data, null),
            createBerSetFromLst(signConfig.getX509CertList()),
            createBerSetFromLst(signConfig.getX509CRLList()),
            pairDigestAndSignInfo.getValue());
        return encodingUnsignedData(content, signedData);
    }

    private Pair<DERSet, DERSet> getSignInfo(byte[] content, CodeSignConfig signConfig)
            throws CodeSignException {
        ASN1EncodableVector signInfoVector = new ASN1EncodableVector();
        ASN1EncodableVector digestVector = new ASN1EncodableVector();
        for (SignAlgorithm signAlgorithm : signConfig.getSignAlgList()) {
            SignerInfo signInfo = createSignInfo(signAlgorithm, content, signConfig);
            signInfoVector.add(signInfo);
            digestVector.add(signInfo.getDigestAlgorithm());
            LOGGER.info("Create a sign info successfully.");
        }
        return Pair.create(new DERSet(digestVector), new DERSet(signInfoVector));
    }

    private SignerInfo createSignInfo(
            SignAlgorithm signAlgorithm, byte[] unsignedDataDigest, CodeSignConfig signConfig)
            throws CodeSignException {
        SecureHashAlgorithm hashAlgorithm = signAlgorithm.getSecureHashAlgorithm();
        byte[] digest = computeDigest(unsignedDataDigest, hashAlgorithm.name());
        ASN1Set authed = getPKCS9Attributes(digest);
        byte[] codeAuthed = getEncoded(authed);
        Pair<String, ? extends AlgorithmParameterSpec> signPair =
            signAlgorithm.getSignAlgorithmAndParams().getPairSignAlgorithmAndParams();
        byte[] signBytes = signConfig.getSignature(
            codeAuthed, signPair.getKey(), signPair.getValue());
        if (signBytes == null) {
            throw new CodeSignException("get signature failed");
        }
        if (signConfig.getX509CertList().isEmpty()) {
            throw new CodeSignException("No certificates configured for sign");
        }
        X509Certificate cert = signConfig.getX509CertList().get(0);
        if (!verifySignFromServer(cert.getPublicKey(), signBytes, signPair, codeAuthed)) {
            throw new CodeSignException("verifySignatureFromServer failed");
        }
        JcaX509CertificateHolder certificateHolder = getJcaX509CertificateHolder(cert);
        return new SignerInfo(
            new ASN1Integer(1),
            new IssuerAndSerialNumber(certificateHolder.getIssuer(), certificateHolder.getSerialNumber()),
            DIGEST_ALG_ID_FINDER.find(hashAlgorithm.getHashAlgorithm()),
            authed,
            SIGN_ALG_ID_FINDER.find(signPair.getKey()),
            new DEROctetString(signBytes),
            null);
    }

    private byte[] computeDigest(byte[] unsignedDataDigest, String algorithm) throws CodeSignException {
        byte[] digest;
        try {
            digest = DigestUtils.computeDigest(unsignedDataDigest, algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new CodeSignException("Invalid algorithm" + e.getMessage(), e);
        }
        return digest;
    }

    private byte[] getEncoded(ASN1Set authed) throws CodeSignException {
        byte[] codeAuthed;
        try {
            codeAuthed = authed.getEncoded();
        } catch (IOException e) {
            throw new CodeSignException("cannot encode authed", e);
        }
        return codeAuthed;
    }

    private JcaX509CRLHolder getJcaX509CRLHolder(X509CRL crl)
            throws CodeSignException {
        JcaX509CRLHolder crlHolder;
        try {
            crlHolder = new JcaX509CRLHolder(crl);
        } catch (CRLException e) {
            throw new CodeSignException("Create crl failed", e);
        }
        return crlHolder;
    }

    private JcaX509CertificateHolder getJcaX509CertificateHolder(X509Certificate cert)
            throws CodeSignException {
        JcaX509CertificateHolder certificateHolder;
        try {
            certificateHolder = new JcaX509CertificateHolder(cert);
        } catch (CertificateEncodingException e) {
            throw new CodeSignException("Create sign info failed", e);
        }
        return certificateHolder;
    }

    private ASN1Set getPKCS9Attributes(byte[] digest) {
        ASN1EncodableVector table = new ASN1EncodableVector();
        Attribute signingTimeAttr = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_signingTime,
            new DERSet(new Time(new Date())));
        Attribute contentTypeAttr = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_contentType,
            new DERSet(PKCSObjectIdentifiers.data));
        Attribute messageDigestAttr = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest,
            new DERSet(new DEROctetString(digest)));
            table.add(signingTimeAttr);
            table.add(contentTypeAttr);
            table.add(messageDigestAttr);
            return new DERSet(table);
    }

    private boolean verifySignFromServer(
            PublicKey publicKey,
            byte[] signBytes,
            Pair<String, ? extends AlgorithmParameterSpec> signPair,
            byte[] authed)
            throws CodeSignException {
        try {
            Signature signature = Signature.getInstance(signPair.getKey());
            signature.initVerify(publicKey);
            if (signPair.getValue() != null) {
                signature.setParameter(signPair.getValue());
            }
            signature.update(authed);
            if (!signature.verify(signBytes)) {
                throw new CodeSignException("Signature verify failed");
            }
            return true;
        } catch (InvalidKeyException | java.security.SignatureException e) {
            LOGGER.error("The generated signature could not be verified "
                    + " using the public key in the certificate", e);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("The generated signature " + signPair.getKey()
                    + " could not be verified using the public key in the certificate", e);
        } catch (InvalidAlgorithmParameterException e) {
            LOGGER.error("The generated signature " + signPair.getValue()
                    + " could not be verified using the public key in the certificate", e);
        }
        return false;
    }

    private ASN1Set createBerSetFromLst(List<?> lists) throws CodeSignException {
        if (lists == null || lists.size() == 0) {
            return null;
        }
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (Object obj : lists) {
            if (obj instanceof X509CRL) {
                vector.add(getJcaX509CRLHolder((X509CRL) obj).toASN1Structure());
            } else if (obj instanceof X509Certificate) {
                vector.add(getJcaX509CertificateHolder((X509Certificate) obj).toASN1Structure());
            }
        }
        return new BERSet(vector);
    }

    private byte[] encodingUnsignedData(byte[] unsignedDataDigest, SignedData signedData) throws CodeSignException {
        byte[] signResult;
        try {
            ContentInfo contentInfo = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);
            signResult = contentInfo.getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new CodeSignException("Failed to encode unsigned data!", e);
        }
        verifySignResult(unsignedDataDigest, signResult);
        return signResult;
    }

    private void verifySignResult(byte[] unsignedDataDigest, byte[] signResult) throws CodeSignException {
        boolean result = false;
        try {
            result = CmsUtils.verifySignDataWithUnsignedDataDigest(unsignedDataDigest, signResult);
        } catch (CMSException e) {
            throw new CodeSignException("Failed to verify signed data and unsigned data digest", e);
        }
        if (!result) {
            throw new CodeSignException("PKCS cms data did not verify");
        }
    }
}
