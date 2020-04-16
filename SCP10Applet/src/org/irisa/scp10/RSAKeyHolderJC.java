package org.irisa.scp10;

/*
 * THIS IMPLEMENTATIONS MAY CONTAINS VULNERABILITIES AND SHOULD NOT BE USED IN PRODUCTION
 */

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class RSAKeyHolderJC {
    private static final short _0 = 0;
    private Cipher rsa;
    public RSAPrivateCrtKey priv;

    public RSAPublicKey pub;
    public boolean isPrivate;
    public short modulusSize;
    public short modulusSizeByte;
    public short eSizeByte;

    public RSAKeyHolderJC(short modulusSize) {
        this.modulusSize = modulusSize;
        this.modulusSizeByte = (short) (modulusSize / 8);
        pub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, modulusSize, false);
        priv = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, modulusSize, false);
        rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        isPrivate = false;
    }

    /**
     * Overwrite the existing public key (exponent and modulus).
     * @param buffer
     *      Buffer containing  the new key.
     * @param eOffset
     *      Offset of the public exponent in buffer.
     * @param eLen
     *      Length of the public exponent.
     * @param nOffset
     *      Offset of the modulus in buffer.
     * @param nLen
     *      Length of the modulus.
     */
    public void setPublicKey(byte[] buffer, short eOffset, short eLen, short nOffset, short nLen) {
        pub.clearKey();
        eSizeByte = eLen;
        pub.setExponent(buffer, eOffset, eLen);
        pub.setModulus(buffer, nOffset, nLen);
    }

    /**
     * Initialize the private key with CRT parameters.
     * @param buffer
     *      Buffer containing all private key parameters.
     * @param pOffset
     * @param pLen
     * @param qOffset
     * @param qLen
     * @param dpOffset
     * @param dpLen
     * @param dqOffset
     * @param dqLen
     * @param pqOffset
     * @param pqLen
     */
    public void setPrivateKey(byte[] buffer, short pOffset, short pLen, short qOffset, short qLen, short dpOffset, short dpLen, short dqOffset, short dqLen, short pqOffset, short pqLen) {
        isPrivate = true;
        priv.clearKey();
        priv.setP(buffer, pOffset, pLen);
        priv.setQ(buffer, qOffset, qLen);
        priv.setDP1(buffer, dpOffset, dpLen);
        priv.setDQ1(buffer, dqOffset, dqLen);
        priv.setPQ(buffer, pqOffset, pqLen);
    }

    /**
     * Perform a modular exponentiation using the public key.
     * @param buffer
     *      Buffer containing the data to exponentiate.
     * @param bOffset
     *      Offset of the data in buffer.
     * @param bLen
     *      Length of the data.
     * @param encryptionMode
     *      Either Cipher.MODE_ENCRYPT or Cipher.MODE_DECRYPT. This is a trick to
     *      be able to encrypt a message even if it is not PKCS1v1.5 compliant.
     * @return
     *      Length of the result.
     */
    public short publicKeyOperation(byte[] buffer, short bOffset, short bLen, byte encryptionMode) {
        rsa.init(pub, encryptionMode);

        return rsa.doFinal(buffer, bOffset, bLen, buffer, bOffset);
    }

    /**
     * Perform a modular exponentiation using the private key.
     * @param buffer
     *      Buffer containing the data to exponentiate.
     * @param bOffset
     *      Offset of the data in buffer.
     * @param bLen
     *      Length of the data.
     * @return
     *  Length of the result.
     */
    public short privateKeyOperation(byte[] buffer, short bOffset, short bLen) {
        if (!isPrivate) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        rsa.init(priv, Cipher.MODE_DECRYPT);

        return rsa.doFinal(buffer, bOffset, bLen, buffer, bOffset);
    }

    /**
     * Decrypt a ciphertext, assuming the padding applied is the one specified in
     * the Global Platform Specification v2.3.1.
     * @param buffer
     *      Buffer containing the ciphertext to decrypt
     * @param bOffset
     *      Offset of the ciphertext in buffer.
     * @param bLen
     *      Length of ciphertext.
     * @return
     *      Length of the plaintext after padding removal.
     */
    public short DecryptPKCS1Deterministic(byte[] buffer, short bOffset, short bLen) {
        short len = privateKeyOperation(buffer, bOffset, bLen);

        if (len != 128 || buffer[bOffset] != 0x00 || buffer[(short) (bOffset+1)] != 0x02) {
            ISOException.throwIt(SCP10Applet.SW_CERT_VERIFICATION_FAILURE);
        }

        short i = (short) (bOffset+2);

        while (buffer[i] != (byte) 0 && i < (short) (len+bOffset-1)) {
            i++;
        }
        // Check if PS is at least 8 bytes long and that we have at least one 00 byte in the decrypted payload
        if ((short) (i-bOffset) < 10 || buffer[i] != 0)
            ISOException.throwIt(SCP10Applet.SW_CERT_VERIFICATION_FAILURE);
        i++;

        // Copy the payload at the beginning of the buffer
        short payloadLength = (short) (bOffset + len - i);
        Util.arrayCopy(buffer, i, buffer, _0, payloadLength);

        return payloadLength;
    }

    /**
     * Produce a PKCS1v1.5 compliant signature of the data in buffer from offset
     * bOffset to bOffset+bLen. The signature is done in-place, meaning the data
     * will be overwritten.
     * @param buffer
     *      Buffer containing all the needed data.
     * @param bOffset
     *      Offset of the data to sign in buffer.
     * @param bLen
     *      Length, in byte, of the data to sign.
     * @param sOffset
     *      Offset to store the signature in buffer. Set it to bOffset to perform
     *      in-place signature.
     * @return
     *      Length of the signature in bytes.
     */
    public short SignPKCS1(byte[] buffer, short bOffset, short bLen, short sOffset) {
        if (!isPrivate) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        Signature signer = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        signer.init(priv, Signature.MODE_SIGN);
        return signer.sign(buffer, bOffset, bLen, buffer, sOffset);
    }

    /**
     * Verify the signature present in buffer at offset sOffset, over the data
     * present in buffer at offset dataOffset to dataOffset+dataLen.
     * The hash function is implicitly known to be SHA-1.
     * @param buffer
     *      Buffer containing the signed data and the signature to verify.
     * @param dataOffset
     *      Offset of the signed data in buffer.
     * @param dataLen
     *      Length of the signed data in buffer.
     * @param sOffset
     *      Offset of the signature in buffer.
     * @return
     *      Validity of the signature.
     */
    public boolean VerifyPKCS1(byte[] buffer, short dataOffset, short dataLen, short sOffset) {
        Signature verifier = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        verifier.init(pub, Signature.MODE_VERIFY);
        return verifier.verify(buffer, dataOffset, dataLen, buffer, sOffset, modulusSizeByte);
    }

    /**
     * Produce an ISO9796-2 compliant signature, embedding a part of the message
     * to allow recovery by the recipient. Since partial message recovery is available,
     * the offset of the data to hash and tha data to embed are distinguished.
     * After producing the signature s, the value min(s, n-s) is stored at offset
     * bOffset in buffer.
     * @param message
     *      Buffer containing all the data to sign.
     * @param toHashOffset
     *      Offset of the data to hash in message. It can overlap with toEmbedOffset.
     * @param toHashLen
     *      Length, in bytes, of the data to hash.
     * @param toEmbedOffset
     *      Offset of the data to embed in the signature. It can overlap with
     *      toHashOffset. For a full message recovery, this must be equal to
     *      toHashOffset.
     * @param toEmbedLen
     *      Length, in bytes, of the data to embed. For a full message recovery,
     *      this must be equal to toHashLen.
     * @param buffer
     *      Buffer in which the signature will be stored.
     * @param bOffset
     *      Offset in buffer where to store the signature.
     * @return
     *      Length, in bytes, of the signature.
     */
    public short SignWithMessageRecovery(byte[] message, short toHashOffset, short toHashLen, short toEmbedOffset, short toEmbedLen, byte[] buffer, short bOffset) {
        // Since it is partial message recovery, we need to compute the digest over all the data, then sign with the data to embed
        MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        if ((short) (toEmbedLen + md.getLength() + 2) > modulusSizeByte || (short) (buffer.length-bOffset) < modulusSizeByte) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }

        // Prepare a buffer containing the partial message and the digest of the full message, along with padding bytes
        buffer[bOffset] = (byte) 0x6A;
        Util.arrayCopy(message, toEmbedOffset, buffer, (short) (bOffset+1), toEmbedLen);
        md.doFinal(message, toHashOffset, toHashLen, buffer, (short) (bOffset+toEmbedLen+1));
        buffer[(short) (bOffset+modulusSizeByte-1)] = (byte) 0xBC;

        // Compute the signature s and set it to min(s, n-s)
        short bLen = privateKeyOperation(buffer, bOffset, modulusSizeByte);
        this.getModulus(buffer, (short) (bOffset+bLen));
        Utils.Subtract(buffer, (short) (bOffset+bLen), bOffset, (short) (bOffset+bLen), bLen);
        if (Utils.CompareConstantTime(buffer, bOffset, (short) (bOffset+bLen)) > 0) {
            Util.arrayCopy(buffer, (short) (bOffset+bLen), buffer, bOffset, bLen);
        }


        return bLen;
    }

    /**
     * Verify an ISO9796-2 compliant signature, and recover the embedded data.
     * @param buffer
     *      Buffer containing all needed data and the signature.
     * @param sigOffset
     *      Offset of the signature in buffer.
     * @param sigLen
     *      Length of the signature.
     * @param additionalDataOffset
     *      Offset of the additional data, in case of partial message recovery.
     * @param additionalDataLen
     *      Length of the additional data, in case of partial message recovery.
     * @param recover
     *      Buffer to store the recovered data.
     * @param recoverOffset
     *      Offset in recover where to store the recovered data.
     * @return
     *      Validity of the signature.
     */
    public boolean VerifyWithMessageRecovery(byte[] buffer, short sigOffset, short sigLen, short additionalDataOffset, short additionalDataLen, byte[] recover, short recoverOffset) {
        short payloadLen = publicKeyOperation(buffer, sigOffset, sigLen, Cipher.MODE_DECRYPT);
        // ISO9796-2 specify that we receive min(s, n-s)
        if (buffer[(short) (sigOffset+payloadLen-1)] != (byte) 0xBC) {
            getModulus(buffer, (short) (recoverOffset+128));
            Utils.Subtract(buffer, (short) (recoverOffset+128), sigOffset, sigOffset, payloadLen);
        }
        MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);

        // Padding checks
        if (buffer[sigOffset] != (byte) 0x6A || buffer[(short) (sigOffset+payloadLen-1)] != (byte) 0xBC) {
            return false;
        }

        // Recover data
        Util.arrayCopy(buffer, (short) (sigOffset + 1), recover, recoverOffset, (short) (payloadLen-22));

        // Compute the digest
        byte[] digest = new byte[md.getLength()];
        md.update(recover, recoverOffset, (short) (payloadLen-22));
        md.doFinal(buffer, additionalDataOffset, additionalDataLen, digest, _0);

        // Check if the computed digest is equal to the
        boolean isValid = true;
        for(short i = 0; i < md.getLength(); i++) {
            isValid &= (digest[i] == buffer[(short) (sigOffset+payloadLen-21+i)]);
        }
        return isValid;
    }

    /**
     * Copy the public exponent at the given offset of the given buffer.
     * @param buffer
     * @param bOffset
     * @return
     *      Length of the public exponent.
     */
    public short getPublicExponent(byte[] buffer, short bOffset) {
        return pub.getExponent(buffer, bOffset);
    }

    /**
     * Copy the modulus at the given offset of the given buffer.
     * @param buffer
     * @param bOffset
     * @return
     *      Length of the modulus.
     */
    public short getModulus(byte[] buffer, short bOffset) {
        return pub.getModulus(buffer, bOffset);
    }

}
