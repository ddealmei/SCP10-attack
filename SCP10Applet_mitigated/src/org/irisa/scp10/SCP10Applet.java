package org.irisa.scp10;

import javacard.framework.*;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class SCP10Applet extends Applet implements ISO7816 {
    private static final short _0 = 0;

    private static short BUFFER_MAX_LENGTH = 1024;
    private static short RESPONSE_MAX_LENGTH = 255;

    // INS byte definition
    private static final byte MANAGE_SECURITY_ENV_INS = (byte) 0x22;
    private static final byte SECURITY_OP_INS = (byte) 0x2A;
    private static final byte EXTERNAL_AUTH_INS = (byte) 0x82;
    private static final byte GET_CHALLENGE_INS = (byte) 0x84;
    private static final byte INTERNAL_AUTH_INS = (byte) 0x88;
    private static final byte GET_DATA_CERT_ISO_INS = (byte) 0xCA;
    private static final byte GET_DATA_CERT_GP_INS = (byte) 0xCB;
    private static final byte GET_MESSAGE_INS = (byte) 0xC0;

    // Protocol constants
    static final byte MUTUAL_AUTHENTICATION = (byte) 0xC1;
    static final byte SCP10_ID = (byte) 0x10;
    static final byte KEY_TRANSPORT_ID = (byte) 0x02;
    static final byte KEY_AGREEMENT_ID = (byte) 0x01;
    static final byte SECURITY_OP_DECRYPT = (byte) 0x2C;
    static final byte SECURITY_OP_VERIF = (byte) 0x2E;
    static final short CERTIFICATE_ID_LENGTH = 8;

    // Security level constants
    static final byte NO_SECURITY_LVL = (byte) 0x00;
    static final byte AUTHENTICATED_LVL = (byte) 0x80;
    static final byte ANY_AUTHENTICATED_LVL = (byte) 0x40;
    static final byte C_DECRYPTION_LVL = (byte) 0x02;
    static final byte C_MAC_LVL = (byte) 0x01;
    static final byte R_DECRYPTION_LVL = (byte) 0x20;
    static final byte R_MAC_LVL = (byte) 0x10;

    // Protocols return codes
    static final short SW_CERT_VERIFICATION_FAILURE = (short) 0x6300;
    static final short SW_ALGO_NOT_SUPPORTED = (short) 0X9484;
    static final short SW_INCORRECT_VALUES = (short) 0x6A80;
    static final short SW_REFERENCED_DATA_NOT_FOUND = (short) 0x6A88;
    static final short SW_DATA_INCOMPLETE = (short) 0X6100;
    static final short SW_EXPECTED_LAST_COMMAND_OF_CHAIN = (short) 0X6883;

    // static variables (asymmetric keys and certificates)
    static private RSAKeyHolderJC sdKey_enc;
    static private RSAKeyHolderJC sdKey_sig;
    static private RSAKeyHolderJC tpKey;
    static private byte[] trustPointID;
    static private final byte[] trustPointCert = {127, 78, -127, -73, 95, 41, 1,
            0, 66, 8, 70, 82, 84, 80, 48, 48, 48, 49, 127, 73, -127, -120, -127,
            -127, -128, -104, 5, 38, 125, 76, 66, -38, 58, -42, 89, 83, 19, -60,
            74, 3, 2, -108, 98, -126, -13, -46, 83, -128, -127, 86, 82, 27, 17,
            35, 9, 119, -38, 58, -118, 21, -79, 127, 104, -60, -36, -93, 108,
            -95, -11, -12, 33, 100, -26, 89, 11, -45, -44, -101, 117, 27, -58,
            -95, -1, 91, -13, -73, -38, -38, 95, 33, 6, 46, 0, -30, -78, -86,
            99, -81, 87, 25, -4, -95, 127, 85, 77, 20, 36, 30, -57, 12, -86, 86,
            -111, 87, -30, -105, 125, 16, 1, 103, 53, -13, 104, 27, 2, -96,
            -127, 60, 119, 32, 39, 110, -94, -37, 54, -90, 97, 124, -92, 107,
            -126, 81, -57, 113, 82, 59, -10, 107, 118, 42, 56, 28, 31, -126, 3,
            1, 0, 1, 95, 32, 8, 70, 82, 84, 80, 48, 48, 48, 49, 95, 37, 6, 1, 9,
            1, 0, 2, 3, 95, 36, 6, 2, 0, 0, 1, 2, 3, 95, 55, -127, -128, -120,
            9, 81, -63, 1, -96, -107, 45, 54, 28, -22, 81, 29, -49, -128, 76,
            117, 59, -2, -29, -38, -93, -41, -99, -16, 84, -18, 36, -84, 83, -7,
            123, 99, 11, 59, -120, -126, 39, 104, 1, -6, 0, -25, -17, -7, 62,
            -118, 108, 74, 16, 118, 124, 23, -118, -28, 127, -64, 32, -121, -77,
            48, -11, -48, -4, -20, 36, -100, 26, 118, -92, -69, 28, -99, 127,
            -40, 84, -105, 89, 103, -35, 58, 97, 77, -67, -3, -42, 81, 8, -70,
            32, -66, -47, -18, 12, 48, 22, 42, 11, -50, -68, 33, 25, -87, -8,
            59, -9, 34, 6, 16, -49, -108, -6, 127, 28, 57, -38, 110, 81, 89,
            -84, 112, 18, -20, -107, 120, 117, 40, -117};

    static private byte[] sdCert_sig = {(byte) 0x7f, (byte) 0x21, (byte) 0x82, (byte) 0x01, (byte) 0x42, (byte) 0x7f,
            (byte) 0x4e, (byte) 0x81, (byte) 0xbb, (byte) 0x5f, (byte) 0x29, (byte) 0x01, (byte) 0x00, (byte) 0x42,
            (byte) 0x08, (byte) 0x46, (byte) 0x52, (byte) 0x54, (byte) 0x50, (byte) 0x30, (byte) 0x30, (byte) 0x30,
            (byte) 0x31, (byte) 0x5f, (byte) 0x4c, (byte) 0x01, (byte) 0x02, (byte) 0x5f, (byte) 0x20, (byte) 0x08,
            (byte) 0x46, (byte) 0x52, (byte) 0x53, (byte) 0x44, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x35,
            (byte) 0x5f, (byte) 0x25, (byte) 0x06, (byte) 0x01, (byte) 0x09, (byte) 0x01, (byte) 0x00, (byte) 0x02,
            (byte) 0x03, (byte) 0x5f, (byte) 0x24, (byte) 0x06, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x02, (byte) 0x03, (byte) 0x7f, (byte) 0x49, (byte) 0x81, (byte) 0x88, (byte) 0x81, (byte) 0x81,
            (byte) 0x80, (byte) 0xa1, (byte) 0x4f, (byte) 0xd3, (byte) 0x3a, (byte) 0x09, (byte) 0x4d, (byte) 0x91,
            (byte) 0x7e, (byte) 0x5e, (byte) 0x91, (byte) 0x68, (byte) 0x3f, (byte) 0xaf, (byte) 0x62, (byte) 0xdc,
            (byte) 0x27, (byte) 0xba, (byte) 0x5f, (byte) 0x60, (byte) 0x24, (byte) 0xd3, (byte) 0x63, (byte) 0x9d,
            (byte) 0x8e, (byte) 0xfe, (byte) 0xe8, (byte) 0xd3, (byte) 0xfe, (byte) 0xeb, (byte) 0xfc, (byte) 0x05,
            (byte) 0xc5, (byte) 0xd0, (byte) 0x58, (byte) 0xfd, (byte) 0x71, (byte) 0x7e, (byte) 0x81, (byte) 0x15,
            (byte) 0x57, (byte) 0x87, (byte) 0xcc, (byte) 0xa1, (byte) 0xaa, (byte) 0xbc, (byte) 0x02, (byte) 0xed,
            (byte) 0xbf, (byte) 0x21, (byte) 0xb7, (byte) 0x92, (byte) 0x02, (byte) 0x29, (byte) 0xf1, (byte) 0x50,
            (byte) 0x85, (byte) 0xdd, (byte) 0xf3, (byte) 0x6d, (byte) 0x8c, (byte) 0xdd, (byte) 0x49, (byte) 0x24,
            (byte) 0x98, (byte) 0x99, (byte) 0xbb, (byte) 0xb0, (byte) 0x78, (byte) 0x17, (byte) 0x2b, (byte) 0xb3,
            (byte) 0x02, (byte) 0xe8, (byte) 0xe2, (byte) 0xf8, (byte) 0x12, (byte) 0x80, (byte) 0x6c, (byte) 0x3e,
            (byte) 0x44, (byte) 0xeb, (byte) 0x0e, (byte) 0x87, (byte) 0xf0, (byte) 0x86, (byte) 0x63, (byte) 0x10,
            (byte) 0xba, (byte) 0x47, (byte) 0x3a, (byte) 0xc7, (byte) 0x05, (byte) 0x94, (byte) 0x0e, (byte) 0x42,
            (byte) 0x52, (byte) 0x52, (byte) 0x29, (byte) 0xbc, (byte) 0xe3, (byte) 0x8c, (byte) 0xd3, (byte) 0x78,
            (byte) 0xc4, (byte) 0x98, (byte) 0x6a, (byte) 0xa0, (byte) 0xce, (byte) 0x2d, (byte) 0xa0, (byte) 0x68,
            (byte) 0x92, (byte) 0x87, (byte) 0xfc, (byte) 0x18, (byte) 0x06, (byte) 0x8f, (byte) 0xfa, (byte) 0xaa,
            (byte) 0xcf, (byte) 0x5c, (byte) 0x44, (byte) 0x25, (byte) 0xa6, (byte) 0xf7, (byte) 0x87, (byte) 0x5a,
            (byte) 0xad, (byte) 0x82, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0x9e, (byte) 0x81,
            (byte) 0x80, (byte) 0x58, (byte) 0xc8, (byte) 0xca, (byte) 0xde, (byte) 0x41, (byte) 0x86, (byte) 0x65,
            (byte) 0xb6, (byte) 0xc5, (byte) 0x76, (byte) 0xa3, (byte) 0x6b, (byte) 0x3b, (byte) 0xcc, (byte) 0x6d,
            (byte) 0x50, (byte) 0xdb, (byte) 0x82, (byte) 0x34, (byte) 0xf0, (byte) 0xbe, (byte) 0x8f, (byte) 0x5a,
            (byte) 0x73, (byte) 0x59, (byte) 0xde, (byte) 0x54, (byte) 0xc0, (byte) 0xb0, (byte) 0x03, (byte) 0xd0,
            (byte) 0x6d, (byte) 0x77, (byte) 0x1b, (byte) 0xda, (byte) 0x81, (byte) 0x11, (byte) 0x71, (byte) 0xa8,
            (byte) 0xab, (byte) 0xab, (byte) 0x81, (byte) 0x45, (byte) 0xe7, (byte) 0xb8, (byte) 0xb2, (byte) 0x81,
            (byte) 0x34, (byte) 0xea, (byte) 0x98, (byte) 0x45, (byte) 0x24, (byte) 0xc9, (byte) 0xe5, (byte) 0xf0,
            (byte) 0xdc, (byte) 0x04, (byte) 0x99, (byte) 0x1c, (byte) 0x2b, (byte) 0x9a, (byte) 0x6d, (byte) 0x0b,
            (byte) 0x79, (byte) 0x63, (byte) 0x79, (byte) 0xd6, (byte) 0xcf, (byte) 0x1f, (byte) 0x55, (byte) 0x49,
            (byte) 0x93, (byte) 0x0c, (byte) 0x74, (byte) 0x60, (byte) 0x2b, (byte) 0xee, (byte) 0x19, (byte) 0x30,
            (byte) 0x18, (byte) 0x40, (byte) 0x8c, (byte) 0x44, (byte) 0xd0, (byte) 0x04, (byte) 0x81, (byte) 0x8a,
            (byte) 0x4c, (byte) 0xf4, (byte) 0xc9, (byte) 0xc9, (byte) 0x17, (byte) 0x6f, (byte) 0xb6, (byte) 0x89,
            (byte) 0xd0, (byte) 0xcd, (byte) 0xff, (byte) 0x88, (byte) 0x63, (byte) 0x1c, (byte) 0xee, (byte) 0xb6,
            (byte) 0xf2, (byte) 0x6e, (byte) 0x06, (byte) 0x13, (byte) 0x29, (byte) 0x57, (byte) 0xbb, (byte) 0x37,
            (byte) 0xa4, (byte) 0xb4, (byte) 0x73, (byte) 0xb7, (byte) 0x25, (byte) 0xe8, (byte) 0x5b, (byte) 0x5d,
            (byte) 0x3e, (byte) 0x6b, (byte) 0xfb, (byte) 0x8f, (byte) 0x7b, (byte) 0x32, (byte) 0xeb, (byte) 0x0c,
            (byte) 0xd6};
    static private byte[] sdCert_enc = {(byte) 0x7f, (byte) 0x21, (byte) 0x82, (byte) 0x01, (byte) 0x42, (byte) 0x7f,
            (byte) 0x4e, (byte) 0x81, (byte) 0xbb, (byte) 0x5f, (byte) 0x29, (byte) 0x01, (byte) 0x00, (byte) 0x42,
            (byte) 0x08, (byte) 0x46, (byte) 0x52, (byte) 0x54, (byte) 0x50, (byte) 0x30, (byte) 0x30, (byte) 0x30,
            (byte) 0x31, (byte) 0x5f, (byte) 0x4c, (byte) 0x01, (byte) 0x01, (byte) 0x5f, (byte) 0x20, (byte) 0x08,
            (byte) 0x46, (byte) 0x52, (byte) 0x53, (byte) 0x44, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x35,
            (byte) 0x5f, (byte) 0x25, (byte) 0x06, (byte) 0x01, (byte) 0x09, (byte) 0x01, (byte) 0x00, (byte) 0x02,
            (byte) 0x03, (byte) 0x5f, (byte) 0x24, (byte) 0x06, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x02, (byte) 0x03, (byte) 0x7f, (byte) 0x49, (byte) 0x81, (byte) 0x88, (byte) 0x81, (byte) 0x81,
            (byte) 0x80, (byte) 0xb8, (byte) 0x03, (byte) 0x32, (byte) 0x61, (byte) 0x06, (byte) 0xc9, (byte) 0xb1,
            (byte) 0xc9, (byte) 0xb3, (byte) 0x12, (byte) 0x17, (byte) 0xb0, (byte) 0x85, (byte) 0x9e, (byte) 0x48,
            (byte) 0x0f, (byte) 0x59, (byte) 0x8f, (byte) 0x6f, (byte) 0x77, (byte) 0xc6, (byte) 0x81, (byte) 0x16,
            (byte) 0x05, (byte) 0xdd, (byte) 0x53, (byte) 0x6c, (byte) 0x85, (byte) 0xa2, (byte) 0xbe, (byte) 0x40,
            (byte) 0x41, (byte) 0x07, (byte) 0x85, (byte) 0x9a, (byte) 0x50, (byte) 0x6f, (byte) 0x23, (byte) 0xe2,
            (byte) 0xfd, (byte) 0x46, (byte) 0x5b, (byte) 0x83, (byte) 0xf5, (byte) 0xfa, (byte) 0xca, (byte) 0xb5,
            (byte) 0x23, (byte) 0xf3, (byte) 0xd4, (byte) 0xae, (byte) 0x0f, (byte) 0x16, (byte) 0xa7, (byte) 0x75,
            (byte) 0x24, (byte) 0x2e, (byte) 0xb4, (byte) 0x83, (byte) 0x76, (byte) 0xf5, (byte) 0xdd, (byte) 0x51,
            (byte) 0x95, (byte) 0xef, (byte) 0xc3, (byte) 0x68, (byte) 0xca, (byte) 0x9a, (byte) 0x05, (byte) 0xe8,
            (byte) 0x33, (byte) 0x03, (byte) 0xa1, (byte) 0x64, (byte) 0xfc, (byte) 0x92, (byte) 0xb1, (byte) 0x67,
            (byte) 0x29, (byte) 0x51, (byte) 0x8c, (byte) 0x67, (byte) 0x9d, (byte) 0xbd, (byte) 0x7d, (byte) 0xe1,
            (byte) 0xbe, (byte) 0x6a, (byte) 0x3d, (byte) 0x76, (byte) 0xeb, (byte) 0xe3, (byte) 0xb2, (byte) 0xd5,
            (byte) 0xf0, (byte) 0xf4, (byte) 0x70, (byte) 0xcf, (byte) 0xb2, (byte) 0xaf, (byte) 0x22, (byte) 0x1c,
            (byte) 0x28, (byte) 0x27, (byte) 0x12, (byte) 0xfb, (byte) 0xcf, (byte) 0x04, (byte) 0x33, (byte) 0x94,
            (byte) 0x67, (byte) 0xaf, (byte) 0x39, (byte) 0x27, (byte) 0xe2, (byte) 0x61, (byte) 0xba, (byte) 0x7a,
            (byte) 0x5d, (byte) 0x57, (byte) 0xe2, (byte) 0x3c, (byte) 0x0a, (byte) 0x04, (byte) 0x92, (byte) 0x8c,
            (byte) 0x7f, (byte) 0x82, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0x9e, (byte) 0x81,
            (byte) 0x80, (byte) 0x15, (byte) 0x87, (byte) 0x95, (byte) 0xe7, (byte) 0xf1, (byte) 0xbb, (byte) 0x0f,
            (byte) 0x4b, (byte) 0xad, (byte) 0x08, (byte) 0x6c, (byte) 0x6a, (byte) 0x22, (byte) 0x2e, (byte) 0x5d,
            (byte) 0x5f, (byte) 0xed, (byte) 0x3d, (byte) 0x50, (byte) 0x8b, (byte) 0x06, (byte) 0x9c, (byte) 0x1f,
            (byte) 0xf5, (byte) 0x64, (byte) 0xfa, (byte) 0x44, (byte) 0x41, (byte) 0x7c, (byte) 0xc0, (byte) 0x4d,
            (byte) 0x11, (byte) 0xec, (byte) 0x8d, (byte) 0xfe, (byte) 0x70, (byte) 0x47, (byte) 0xb4, (byte) 0x0e,
            (byte) 0x63, (byte) 0x2b, (byte) 0x61, (byte) 0xf6, (byte) 0x37, (byte) 0xa1, (byte) 0x2f, (byte) 0x9b,
            (byte) 0x1c, (byte) 0xbb, (byte) 0x13, (byte) 0xe5, (byte) 0x0d, (byte) 0xdd, (byte) 0xe4, (byte) 0x1e,
            (byte) 0xa7, (byte) 0x58, (byte) 0x9f, (byte) 0xc2, (byte) 0xd9, (byte) 0x71, (byte) 0x4c, (byte) 0xdd,
            (byte) 0xa9, (byte) 0x16, (byte) 0xae, (byte) 0x6d, (byte) 0x8e, (byte) 0x9e, (byte) 0x8c, (byte) 0x18,
            (byte) 0xbf, (byte) 0x2b, (byte) 0xce, (byte) 0xa5, (byte) 0x11, (byte) 0x1e, (byte) 0xc5, (byte) 0x79,
            (byte) 0xde, (byte) 0xcd, (byte) 0xa0, (byte) 0x13, (byte) 0x58, (byte) 0xaf, (byte) 0x25, (byte) 0xea,
            (byte) 0xe5, (byte) 0x05, (byte) 0x20, (byte) 0x29, (byte) 0xca, (byte) 0x00, (byte) 0xc5, (byte) 0x4b,
            (byte) 0x62, (byte) 0x0f, (byte) 0x65, (byte) 0x08, (byte) 0x3d, (byte) 0xea, (byte) 0x25, (byte) 0x0d,
            (byte) 0x97, (byte) 0x37, (byte) 0xb9, (byte) 0xe7, (byte) 0x0b, (byte) 0x40, (byte) 0xe8, (byte) 0xe9,
            (byte) 0x33, (byte) 0x41, (byte) 0x7e, (byte) 0xd1, (byte) 0x74, (byte) 0x8c, (byte) 0x95, (byte) 0x2e,
            (byte) 0x4b, (byte) 0x52, (byte) 0x8c, (byte) 0xa2, (byte) 0x66, (byte) 0x46, (byte) 0x83, (byte) 0xd6,
            (byte) 0xd4};

    // Instance variables
    private RandomData rng;

    // Session parameters
    private byte authenticationMode = 0;
    private byte keyExchangeMode;
    private boolean doCertVerification = true;
    private byte currentSecurityLvl;
    private byte sessionSecurityLvl;
    // Sum up all commands received during this session, in this logical channel
    private byte previousCommands = 0;
    // Store the last command to keep track of the command immediately preceding
    // the processed command
    private byte lastCommand = 0;
    private boolean isActiveSession = false;
    private boolean terminated = false;

    private byte[] challenge;
    private short challengeLen;

    private byte[] secretOCE;
    private byte[] secretSD;

    private RSAKeyHolderJC currentPublicKey_enc;
    private RSAKeyHolderJC currentPublicKey_sig;
    private byte[] currentID_enc;
    private byte[] currentID_sig;

    private boolean chain = false;
    private byte chain_ins = 0;
    private short chain_p1p2 = 0;

    private byte[] buffer;
    private short out_left = 0;
    private short out_sent = 0;
    private short in_received = 0;
    // Byte array to store at most two CRTs, containing session keys (encryption and authentication)
    private short nbCrts;
    private short[] crtOffsets;
    private byte[] crts;

    private short bLen = 0;

    private SCP10Applet(byte[] bArray, short bOffset, byte bLength) {
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        // Set SD key
        sdKey_sig = new RSAKeyHolderJC((short) 1024);
        CertificateJC.setRSAPublicKey(sdCert_sig, _0, (short) sdCert_sig.length, sdKey_sig);
        byte[] key_sig = {(byte) 0xc1, (byte) 0xce, (byte) 0xd2, (byte) 0xb6, (byte) 0x6b, (byte) 0x80, (byte) 0x4e,
                (byte) 0xb2, (byte) 0x5e, (byte) 0x15, (byte) 0xb7, (byte) 0xbd, (byte) 0x8d, (byte) 0x5a, (byte) 0x81,
                (byte) 0x3c, (byte) 0xd9, (byte) 0x71, (byte) 0xc0, (byte) 0xe6, (byte) 0x1b, (byte) 0x7d, (byte) 0xac,
                (byte) 0xd8, (byte) 0x04, (byte) 0x4c, (byte) 0x52, (byte) 0xe5, (byte) 0xc9, (byte) 0x17, (byte) 0x93,
                (byte) 0x74, (byte) 0xca, (byte) 0x0d, (byte) 0xf1, (byte) 0xb1, (byte) 0xf4, (byte) 0xd3, (byte) 0xee,
                (byte) 0xa8, (byte) 0xd1, (byte) 0x61, (byte) 0x71, (byte) 0x17, (byte) 0xfc, (byte) 0x2f, (byte) 0x76,
                (byte) 0x7e, (byte) 0x67, (byte) 0x32, (byte) 0x64, (byte) 0x57, (byte) 0xf1, (byte) 0x34, (byte) 0xc3,
                (byte) 0x57, (byte) 0xad, (byte) 0x06, (byte) 0xc7, (byte) 0x7b, (byte) 0xa6, (byte) 0x58, (byte) 0x33,
                (byte) 0x95, (byte) 0xd5, (byte) 0x13, (byte) 0x78, (byte) 0xef, (byte) 0xf7, (byte) 0x9d, (byte) 0x41,
                (byte) 0x95, (byte) 0x16, (byte) 0x51, (byte) 0xa7, (byte) 0x17, (byte) 0x2c, (byte) 0x39, (byte) 0x56,
                (byte) 0x2b, (byte) 0x80, (byte) 0x08, (byte) 0x2d, (byte) 0x55, (byte) 0xd1, (byte) 0x03, (byte) 0x2b,
                (byte) 0x88, (byte) 0xde, (byte) 0xc3, (byte) 0x57, (byte) 0x3d, (byte) 0xc4, (byte) 0x4e, (byte) 0x52,
                (byte) 0xaa, (byte) 0x0c, (byte) 0x83, (byte) 0x38, (byte) 0x30, (byte) 0xe8, (byte) 0xeb, (byte) 0xe5,
                (byte) 0xc7, (byte) 0x1c, (byte) 0xb3, (byte) 0xad, (byte) 0x36, (byte) 0x85, (byte) 0xcc, (byte) 0xb6,
                (byte) 0x76, (byte) 0x3e, (byte) 0x26, (byte) 0x30, (byte) 0xce, (byte) 0xf0, (byte) 0x53, (byte) 0x54,
                (byte) 0x0e, (byte) 0x5f, (byte) 0xdd, (byte) 0x81, (byte) 0x7a, (byte) 0xbe, (byte) 0x1c, (byte) 0xc4,
                (byte) 0xb9, (byte) 0x8a, (byte) 0x00, (byte) 0x85, (byte) 0x96, (byte) 0x13, (byte) 0x92, (byte) 0x37,
                (byte) 0x77, (byte) 0x56, (byte) 0xfb, (byte) 0x4b, (byte) 0xec, (byte) 0x93, (byte) 0x5c, (byte) 0xa0,
                (byte) 0xad, (byte) 0xfd, (byte) 0x7f, (byte) 0xbc, (byte) 0x85, (byte) 0x9d, (byte) 0x89, (byte) 0xad,
                (byte) 0xab, (byte) 0xdb, (byte) 0xd3, (byte) 0xa5, (byte) 0x2b, (byte) 0xae, (byte) 0x37, (byte) 0x35,
                (byte) 0x6e, (byte) 0x71, (byte) 0xf9, (byte) 0xdf, (byte) 0xe2, (byte) 0x81, (byte) 0x9c, (byte) 0xef,
                (byte) 0x52, (byte) 0x12, (byte) 0x55, (byte) 0xba, (byte) 0x3c, (byte) 0x03, (byte) 0xfc, (byte) 0x9f,
                (byte) 0xf9, (byte) 0x7d, (byte) 0xee, (byte) 0x29, (byte) 0xf9, (byte) 0x5c, (byte) 0xed, (byte) 0xdf,
                (byte) 0x32, (byte) 0xed, (byte) 0x27, (byte) 0xe8, (byte) 0x9f, (byte) 0xa9, (byte) 0x61, (byte) 0x20,
                (byte) 0xc9, (byte) 0x6b, (byte) 0x17, (byte) 0xa5, (byte) 0x62, (byte) 0x1e, (byte) 0xb6, (byte) 0xe8,
                (byte) 0x1e, (byte) 0x71, (byte) 0xa0, (byte) 0x4a, (byte) 0x75, (byte) 0xe8, (byte) 0x21, (byte) 0x4d,
                (byte) 0x41, (byte) 0x01, (byte) 0xd1, (byte) 0x9a, (byte) 0x4f, (byte) 0x96, (byte) 0x84, (byte) 0x9c,
                (byte) 0x5d, (byte) 0xe7, (byte) 0x70, (byte) 0x90, (byte) 0xa9, (byte) 0x97, (byte) 0xbf, (byte) 0xb1,
                (byte) 0xe6, (byte) 0x8b, (byte) 0xf1, (byte) 0x6b, (byte) 0xcd, (byte) 0x91, (byte) 0x53, (byte) 0xf7,
                (byte) 0x22, (byte) 0x13, (byte) 0x37, (byte) 0xef, (byte) 0x68, (byte) 0x06, (byte) 0xe9, (byte) 0xb4,
                (byte) 0x0f, (byte) 0x4b, (byte) 0xff, (byte) 0x4f, (byte) 0xea, (byte) 0xc2, (byte) 0x79, (byte) 0x6f,
                (byte) 0x36, (byte) 0xe6, (byte) 0x51, (byte) 0xe3, (byte) 0x60, (byte) 0xf8, (byte) 0xaa, (byte) 0x66,
                (byte) 0xe9, (byte) 0x6e, (byte) 0xcc, (byte) 0x66, (byte) 0x72, (byte) 0xe4, (byte) 0x7f, (byte) 0x04,
                (byte) 0x5f, (byte) 0x38, (byte) 0x90, (byte) 0xc5, (byte) 0x89, (byte) 0xf8, (byte) 0xbb, (byte) 0x2e,
                (byte) 0x09, (byte) 0x5b, (byte) 0x83, (byte) 0x93, (byte) 0x54, (byte) 0x6d, (byte) 0x13, (byte) 0x90,
                (byte) 0xe8, (byte) 0xe8, (byte) 0xff, (byte) 0x18, (byte) 0x5f, (byte) 0x04, (byte) 0x01, (byte) 0x0c,
                (byte) 0x63, (byte) 0x3f, (byte) 0x4d, (byte) 0xa2, (byte) 0xd1, (byte) 0xdf, (byte) 0x99, (byte) 0x2b,
                (byte) 0x91, (byte) 0xd3, (byte) 0x24, (byte) 0x29, (byte) 0x08, (byte) 0x99, (byte) 0x26, (byte) 0x22,
                (byte) 0xee, (byte) 0x97, (byte) 0xda, (byte) 0x48, (byte) 0x81, (byte) 0xdc, (byte) 0xcd, (byte) 0x25,
                (byte) 0xab, (byte) 0xf6, (byte) 0xc5, (byte) 0xe1, (byte) 0xde, (byte) 0x08, (byte) 0x64, (byte) 0x69,
                (byte) 0x18};
        sdKey_sig.setPrivateKey(key_sig, _0, (short) 64, (short) 64, (short) 64, (short) 128, (short) 64, (short) 192, (short) 64, (short) 256, (short) 64);

        sdKey_enc = new RSAKeyHolderJC((short) 1024);
        CertificateJC.setRSAPublicKey(sdCert_enc, _0, (short) sdCert_enc.length, sdKey_enc);
        byte[] key_enc = {(byte) 0xce, (byte) 0x0b, (byte) 0xef, (byte) 0x54, (byte) 0x00, (byte) 0xa8, (byte) 0xa8,
                (byte) 0x3a, (byte) 0x70, (byte) 0x9b, (byte) 0xbd, (byte) 0xeb, (byte) 0xfe, (byte) 0xee, (byte) 0xa7,
                (byte) 0xb8, (byte) 0xca, (byte) 0x14, (byte) 0xc9, (byte) 0xa7, (byte) 0xe1, (byte) 0xfc, (byte) 0x14,
                (byte) 0x17, (byte) 0xd7, (byte) 0x95, (byte) 0x7a, (byte) 0xb7, (byte) 0x3a, (byte) 0x15, (byte) 0x4c,
                (byte) 0x87, (byte) 0x0b, (byte) 0xab, (byte) 0xb9, (byte) 0x2e, (byte) 0x25, (byte) 0x5d, (byte) 0x46,
                (byte) 0x28, (byte) 0x7c, (byte) 0x45, (byte) 0x63, (byte) 0x50, (byte) 0x36, (byte) 0x45, (byte) 0x6e,
                (byte) 0x21, (byte) 0x5c, (byte) 0x59, (byte) 0x76, (byte) 0x96, (byte) 0x5b, (byte) 0x74, (byte) 0x2c,
                (byte) 0x20, (byte) 0x0d, (byte) 0x2e, (byte) 0x7a, (byte) 0x68, (byte) 0x81, (byte) 0xce, (byte) 0x4d,
                (byte) 0x1d, (byte) 0xe4, (byte) 0x9f, (byte) 0xbc, (byte) 0x9e, (byte) 0xc9, (byte) 0x28, (byte) 0x22,
                (byte) 0xea, (byte) 0xc7, (byte) 0x6c, (byte) 0x10, (byte) 0xf8, (byte) 0xe3, (byte) 0x35, (byte) 0xe9,
                (byte) 0x3e, (byte) 0x0b, (byte) 0x1c, (byte) 0xd8, (byte) 0x9b, (byte) 0xd9, (byte) 0xd3, (byte) 0xa8,
                (byte) 0xea, (byte) 0xc4, (byte) 0xe1, (byte) 0x3f, (byte) 0x7a, (byte) 0xaf, (byte) 0x72, (byte) 0xb3,
                (byte) 0x5c, (byte) 0x1d, (byte) 0x4a, (byte) 0x5d, (byte) 0xbc, (byte) 0xba, (byte) 0xf4, (byte) 0xf5,
                (byte) 0x4c, (byte) 0xe3, (byte) 0x20, (byte) 0x2e, (byte) 0x5f, (byte) 0x22, (byte) 0xf0, (byte) 0x01,
                (byte) 0x06, (byte) 0x3d, (byte) 0x7c, (byte) 0xee, (byte) 0x15, (byte) 0xe8, (byte) 0x0d, (byte) 0x1c,
                (byte) 0x33, (byte) 0x18, (byte) 0x8a, (byte) 0xf8, (byte) 0x35, (byte) 0xb0, (byte) 0x88, (byte) 0xb9,
                (byte) 0x4b, (byte) 0xab, (byte) 0xb3, (byte) 0xac, (byte) 0x63, (byte) 0xaf, (byte) 0x0c, (byte) 0xdc,
                (byte) 0xeb, (byte) 0x9e, (byte) 0x2d, (byte) 0x5a, (byte) 0x8e, (byte) 0x0f, (byte) 0xea, (byte) 0x26,
                (byte) 0xe0, (byte) 0x49, (byte) 0x9e, (byte) 0x1b, (byte) 0x11, (byte) 0x88, (byte) 0xb3, (byte) 0x3c,
                (byte) 0xb7, (byte) 0x45, (byte) 0x92, (byte) 0xae, (byte) 0x29, (byte) 0x84, (byte) 0x00, (byte) 0x7d,
                (byte) 0xbe, (byte) 0x47, (byte) 0xce, (byte) 0x79, (byte) 0x49, (byte) 0x68, (byte) 0x1f, (byte) 0x9b,
                (byte) 0x38, (byte) 0x5f, (byte) 0x9e, (byte) 0x9f, (byte) 0x0d, (byte) 0x17, (byte) 0xbc, (byte) 0xb1,
                (byte) 0xf2, (byte) 0xa0, (byte) 0xf7, (byte) 0x78, (byte) 0x68, (byte) 0x01, (byte) 0x9c, (byte) 0x04,
                (byte) 0xad, (byte) 0x4c, (byte) 0xee, (byte) 0xbf, (byte) 0x58, (byte) 0xd9, (byte) 0x5a, (byte) 0xe6,
                (byte) 0x4d, (byte) 0xd0, (byte) 0xa7, (byte) 0xec, (byte) 0xf9, (byte) 0x2a, (byte) 0x74, (byte) 0x04,
                (byte) 0x32, (byte) 0x2c, (byte) 0xa1, (byte) 0xb7, (byte) 0x77, (byte) 0xbf, (byte) 0xbe, (byte) 0xc3,
                (byte) 0x4a, (byte) 0x09, (byte) 0xd0, (byte) 0x60, (byte) 0xed, (byte) 0x14, (byte) 0xc7, (byte) 0xf5,
                (byte) 0x61, (byte) 0x97, (byte) 0x20, (byte) 0x50, (byte) 0xd4, (byte) 0x42, (byte) 0xee, (byte) 0x37,
                (byte) 0x3e, (byte) 0x39, (byte) 0xc9, (byte) 0x56, (byte) 0x75, (byte) 0xda, (byte) 0x57, (byte) 0x98,
                (byte) 0xcd, (byte) 0x7c, (byte) 0x79, (byte) 0x31, (byte) 0x79, (byte) 0x48, (byte) 0xa4, (byte) 0xac,
                (byte) 0xfa, (byte) 0xaa, (byte) 0x01, (byte) 0xac, (byte) 0x35, (byte) 0xb8, (byte) 0x1c, (byte) 0xc7,
                (byte) 0x00, (byte) 0xe7, (byte) 0x44, (byte) 0x66, (byte) 0x36, (byte) 0x72, (byte) 0x10, (byte) 0xc6,
                (byte) 0xb3, (byte) 0xa7, (byte) 0x3c, (byte) 0x8d, (byte) 0xb8, (byte) 0x54, (byte) 0x05, (byte) 0xb3,
                (byte) 0x4e, (byte) 0xc6, (byte) 0x4d, (byte) 0x4d, (byte) 0x13, (byte) 0xf1, (byte) 0x86, (byte) 0x3d,
                (byte) 0xb9, (byte) 0x72, (byte) 0xd6, (byte) 0x3c, (byte) 0xa2, (byte) 0xf4, (byte) 0xf6, (byte) 0x63,
                (byte) 0x05, (byte) 0x29, (byte) 0x76, (byte) 0x09, (byte) 0xf9, (byte) 0x70, (byte) 0x28, (byte) 0xec,
                (byte) 0xa3, (byte) 0x8f, (byte) 0x5a, (byte) 0xd1, (byte) 0x52, (byte) 0x70, (byte) 0xfe, (byte) 0x37,
                (byte) 0xef, (byte) 0x2f, (byte) 0x32, (byte) 0x5a, (byte) 0xc7, (byte) 0x24, (byte) 0x73, (byte) 0x99,
                (byte) 0x6a, (byte) 0xec, (byte) 0xfd, (byte) 0x84, (byte) 0x01, (byte) 0x8b, (byte) 0x01, (byte) 0x09,
                (byte) 0x81, (byte) 0x86, (byte) 0xb8, (byte) 0x8f, (byte) 0x15, (byte) 0xc9, (byte) 0x08, (byte) 0x94,
                (byte) 0x28};
        sdKey_enc.setPrivateKey(key_enc, _0, (short) 64, (short) 64, (short) 64, (short) 128, (short) 64, (short) 192, (short) 64, (short) 256, (short) 64);

        // Init Trust Point public key
        tpKey = new RSAKeyHolderJC((short) 1024);
        currentPublicKey_enc = new RSAKeyHolderJC((short) 1024);
        currentPublicKey_sig = new RSAKeyHolderJC((short) 1024);
        CertificateJC.setRSAPublicKey(trustPointCert, _0, (short) trustPointCert.length, currentPublicKey_enc);
        CertificateJC.setRSAPublicKey(trustPointCert, _0, (short) trustPointCert.length, currentPublicKey_sig);
        CertificateJC.setRSAPublicKey(trustPointCert, _0, (short) trustPointCert.length, tpKey);

        // Init buffers
        buffer = JCSystem.makeTransientByteArray(BUFFER_MAX_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        challenge = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        secretOCE = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        secretSD = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        crts = JCSystem.makeTransientByteArray((short) (CRTJC.MAX_CRT_SIZE*5), JCSystem.CLEAR_ON_DESELECT);

        crtOffsets = new short[5];
        currentID_enc = new byte[CERTIFICATE_ID_LENGTH];
        currentID_sig = new byte[CERTIFICATE_ID_LENGTH];

        trustPointID = new byte[CERTIFICATE_ID_LENGTH];
        CertificateJC.getHolderRef(trustPointCert, _0, (short) trustPointCert.length, trustPointID, _0);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SCP10Applet(bArray, bOffset, bLength);
    }

    private void resetInstanceVariables() {
        resetChaining();
        isActiveSession = false;
        nbCrts = 0;
        out_sent = 0;
        out_left = 0;
        sessionSecurityLvl = NO_SECURITY_LVL;
        currentSecurityLvl = NO_SECURITY_LVL;
        keyExchangeMode = KEY_TRANSPORT_ID;
        authenticationMode = MUTUAL_AUTHENTICATION;
        doCertVerification = false;
        terminated = false;

        Util.arrayCopy(trustPointID, _0, currentID_enc, _0, CERTIFICATE_ID_LENGTH);
        Util.arrayCopy(trustPointID, _0, currentID_sig, _0, CERTIFICATE_ID_LENGTH);

        // Clear sensitive data
        Util.arrayFillNonAtomic(challenge, _0, (short) challenge.length, (byte) 0);
        Util.arrayFillNonAtomic(secretOCE, _0, (short) secretOCE.length, (byte) 0);
        Util.arrayFillNonAtomic(secretSD, _0, (short) secretSD.length, (byte) 0);
        Util.arrayFillNonAtomic(buffer, _0, (short) buffer.length, (byte) 0);
        Util.arrayFillNonAtomic(crts, _0, (short) crts.length, (byte) 0);
        for (short i = 0; i < (short) crtOffsets.length; i++) {
            crtOffsets[i] = _0;
        }
    }

    public boolean select() {
        resetInstanceVariables();

        return true;
    }

    public void process(final APDU apdu) {
        if (selectingApplet())
            return;

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];
        byte p1 = buffer[OFFSET_P1];
        byte p2 = buffer[OFFSET_P2];

        short status = SW_NO_ERROR;
        short le = 0;
        try {
            // Take care of command chaining if needed
            commandChaining(apdu);

            if (terminated && ins != MANAGE_SECURITY_ENV_INS) {
				ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
			}

            // TODO process the different CLA

            switch (ins) {
                case GET_MESSAGE_INS:
                    // Deal with it in the finally clause
                    break;
                case GET_DATA_CERT_GP_INS:
                case GET_DATA_CERT_ISO_INS:
                    le = sendCertificate(Util.makeShort(p1, p2));
                    break;

                case MANAGE_SECURITY_ENV_INS:
                    // If a session is active when receiving this command, it
                    // shall be terminated regardless of the validity of the
                    // command
                    if (isActiveSession)
                        ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
                    // Check options
                    if (p1 != (byte) 0x81 && p1 != (byte) 0xC1)
                        ISOException.throwIt(SW_WRONG_P1P2);
                    if (p2 != (byte) 0xA4 && p2 != (byte) 0xB6)
                        ISOException.throwIt(SW_WRONG_P1P2);

                    manageSecurityEnvironment(p1, p2);
                    break;

                case SECURITY_OP_INS:
                    if (p1 == (byte) 0x00) {
                        if (doCertVerification)
                            verifyCert();
                    }
                    else if (p1 == (byte) 0x80)
                        decipher();
                    else
                        ISOException.throwIt(SW_INCORRECT_P1P2);
                    break;

                case GET_CHALLENGE_INS:
                    if (!isActiveSession)
                        ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
                    // Check for previous operations (immediately before or not)
                    if ((previousCommands & MANAGE_SECURITY_ENV_INS) != MANAGE_SECURITY_ENV_INS
                            && (previousCommands & SECURITY_OP_VERIF) != SECURITY_OP_VERIF)
                        ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
                    if (p1 != 0 || p2 != 0)
                        ISOException.throwIt(SW_INCORRECT_P1P2);

                    le = sendChallenge();
                    break;

                case EXTERNAL_AUTH_INS:
                    if (!isActiveSession || lastCommand != GET_CHALLENGE_INS)
                        ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);

                    externalAuthenticate();
                    break;

                case INTERNAL_AUTH_INS:
                    if (!isActiveSession)
                        ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
                    // Check for previous operations
                    if (lastCommand != EXTERNAL_AUTH_INS)
                        ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);

                    if (authenticationMode == MUTUAL_AUTHENTICATION)
                        le = internalAuthenticate();
                    break;

                default:
                    // good practice: If you don't know the INStruction, say so:
                    ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            }
        } catch(ISOException e) {
            status = e.getReason();
        } finally {
            // Keep track of previous and last commands
            lastCommand = ins;
            previousCommands |= ins;
            if (status != (short) 0x9000) {
                // Send the exception that was thrown
                sendException(apdu, status);
            }
            else {
                // GET RESPONSE, for response chaining
                if (ins == (byte) 0xC0) {
                    sendNext(apdu);
                }
                else {
                    sendBuffer(apdu, le);
                }
            }
        }
    }

    /**
     * Receive the data (SCPid || i) with a potential reference to public and
     * private key. Allow to setup some session parameters.
     * @param p1
     *          Choose between external and mutual authentication
     * @param p2
     *          Make a certificate verification card side or not
     */
    private void manageSecurityEnvironment(byte p1, byte p2) {
        authenticationMode = p1;
        doCertVerification = (p2 == (byte) 0xB6);

        if (in_received < 3)
            ISOException.throwIt(SW_WRONG_LENGTH);
        
        short bOff = 0;

        // Check first tag
        if (buffer[bOff++] != (byte) 0x80)
            ISOException.throwIt(SW_DATA_INVALID);
        if (buffer[bOff++] != SCP10_ID)
            ISOException.throwIt(SW_ALGO_NOT_SUPPORTED);

        // We only support Key Agreement + Signature with recovery and
        // Key Transport + Signature without recovery
        keyExchangeMode = buffer[bOff++];
        if (keyExchangeMode != KEY_TRANSPORT_ID && keyExchangeMode != KEY_AGREEMENT_ID)
            ISOException.throwIt(SW_ALGO_NOT_SUPPORTED);

        if (keyExchangeMode == KEY_AGREEMENT_ID && authenticationMode != MUTUAL_AUTHENTICATION)
            ISOException.throwIt(SW_ALGO_NOT_SUPPORTED);

        // Parse conditional fields
        while (bOff < in_received) {
            // TODO: Public key and private key references, TLV encoded
            if (buffer[bOff] == (byte) 0x83) {
                bOff++;

                // Parse public key reference, and set it in the verification key holder
            }
            else if (buffer[bOff] == (byte) 0x84 ){
                bOff++;
                // Parse private key reference, and set it in the verification key holder
            }
            else {
                ISOException.throwIt(SW_DATA_INVALID);
            }
        }

        isActiveSession = true;
    }

    /**
     * Send the all certification chain to OCE
     * @param p1p2
     *      Option of the APDU, defining the type of data to return. Only 0x7f21
     *      is currently supported.
     * @return
     *      Length of the data to send
     */
    private short sendCertificate(short p1p2) {
        // The command may be issued at any time
        // TODO: we may need to check the current security level to see if it fits
        // For now, only support the "get the default certificate" command
        if (p1p2 == CertificateJC.CVC_TAG) {
            // Send both certificates
            bLen = Util.arrayCopy(sdCert_sig, _0, buffer, _0, (short) sdCert_sig.length);
            bLen = Util.arrayCopy(sdCert_enc, _0, buffer, bLen, (short) sdCert_enc.length);
        }
        else {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        }

        return bLen;
    }

    /**
     * Check the validity of the CVC. Only verify the issuer and the signature.
     * If this elements are valid, wwe initialize OCE's public with the certificate
     */
    private void verifyCert() {
        bLen = CertificateJC.getCertificateBody(buffer, _0, in_received, buffer, in_received);

        // Get the issuer of the certificate, and check if it is TrustPoint
        CertificateJC.getIssuerRef(buffer, _0, in_received, buffer, (short) (in_received+bLen));
        Util.arrayCopy(trustPointID, _0, buffer, (short) (in_received+bLen+CERTIFICATE_ID_LENGTH), CERTIFICATE_ID_LENGTH);
        if (Utils.CompareConstantTime(buffer, (short) (in_received+bLen), (short) (in_received+bLen+CERTIFICATE_ID_LENGTH)) != 0)
            ISOException.throwIt(SW_CERT_VERIFICATION_FAILURE);

        // Check the signature
        CertificateJC.getSignature(buffer, _0, in_received, buffer, _0);
        if (!tpKey.VerifyPKCS1(buffer, in_received, bLen, _0)) {
            ISOException.throwIt(SW_CERT_VERIFICATION_FAILURE);
        }

        // Get the key usage
        byte usage = CertificateJC.getKeyUsage(buffer, in_received, bLen);
        if ((usage & CertificateJC.KU_ENC) == CertificateJC.KU_ENC) {
            CertificateJC.setRSAPublicKey(buffer, in_received, bLen, currentPublicKey_enc);
            CertificateJC.getHolderRef(buffer, in_received, bLen, currentID_enc, _0);
        }
        if ((usage & CertificateJC.KU_SIG) == CertificateJC.KU_SIG) {
            CertificateJC.setRSAPublicKey(buffer, in_received, bLen, currentPublicKey_sig);
            CertificateJC.getHolderRef(buffer, in_received, bLen, currentID_sig, _0);
        }

        isActiveSession = true;
    }

    /**
     * Recover the plaintext and parse the CRT (recovering keys in keyTransport
     * mode)
     */
    private void decipher() {
        // Check for previous operations (immediately before or not)
        if ((previousCommands & MANAGE_SECURITY_ENV_INS) != MANAGE_SECURITY_ENV_INS
                && (previousCommands & SECURITY_OP_VERIF) != SECURITY_OP_VERIF){
        	ISOException.throwIt(SW_ALGO_NOT_SUPPORTED);
        }

        try {
            // Recover the plaintext and parse the CRT (recovering keys in keyTransport mode)
            bLen = sdKey_enc.DecryptOAEP(buffer, _0, in_received);

            // Recover the security level
            short offset = (short) (TLVParserJC.getElement(buffer, _0, in_received, buffer, _0, (short) 0xD3) + 2);
            sessionSecurityLvl = buffer[0];
            
            // Read all CRT in the payload
            short len;
            short crtOff = 0;
            while (offset < (short) (bLen - 1) && nbCrts < 5) {
                crtOffsets[nbCrts] = crtOff;
                len = CRTJC.getCRT(buffer, offset, crts, crtOff);
                nbCrts++;
                offset += len;
                crtOff += len;
            }
        }
        catch (ISOException e) {
            // If an error occurred during the general process, return a unique error
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        isActiveSession = true;
    }

    /**
     * Generates a random challenge to send to OCE. The challenge is 8 bytes
     * long in key agreement mode, and 16 bytes mode in key exchange mode
     * @return
     *      Length of the data to send back
     */
    private short sendChallenge() {
        if (in_received != 0)
            ISOException.throwIt(SW_WRONG_LENGTH);

        challengeLen = (short) ((keyExchangeMode == KEY_AGREEMENT_ID) ? 8 : 16);
        rng.generateData(challenge, _0, challengeLen);
        Util.arrayCopy(challenge, _0, buffer, _0, challengeLen);

        return challengeLen;
    }

    /**
     * Authenticate the OCE by checking the challenge's signature with OCE's
     * public key.
     * For keyTransport, a simple PKCS1v1.5 verification is done.
     * For key agreement, a verification with message recovery allow to get OCE
     * secret, which is needed to compute the session key.
     */
    private void externalAuthenticate() {
        // The total length is the offset of the last, plus its length
        short crtTotalSize = (short) (crtOffsets[(short) (nbCrts-1)] + CRTJC.getCRTLen(crts, crtOffsets[(short) (nbCrts-1)]));
        if (keyExchangeMode == KEY_AGREEMENT_ID) {
            // Perform a raw decryption before verifying the signature
            bLen = sdKey_enc.privateKeyOperation(buffer, _0, in_received);

            // Append the additional data to buffer (challenge and card id)
            Util.arrayCopy(challenge, _0, buffer, bLen, challengeLen);
            CertificateJC.getHolderRef(sdCert_sig, _0, (short) sdCert_sig.length, buffer, (short) (bLen + challengeLen));

            // Recovered data will be stored after the signature and the additional data
            short recoveredOffset = (short) (bLen+ challengeLen + CERTIFICATE_ID_LENGTH);

            if (!currentPublicKey_sig.VerifyWithMessageRecovery(buffer, _0, bLen,
                    bLen, (short) (challengeLen +CERTIFICATE_ID_LENGTH), buffer,
                    recoveredOffset))
                ISOException.throwIt(SW_CERT_VERIFICATION_FAILURE);

            // Check recovered data format
            // size_n(128) - secret(32) - hash(20) - sig_pad(2) - security_tlv(3) - crt
            short paddLen = (short) (sdKey_sig.modulusSizeByte - secretOCE.length - 20 - 2 - 3 - crtTotalSize);
            bLen = (short) (recoveredOffset+paddLen);
            boolean isValid = buffer[bLen++] == (byte) 0xD3;
            isValid &= buffer[bLen++] == (byte) 0x01;
            isValid &= buffer[bLen++] == sessionSecurityLvl;
            // Check CRT contents
            for (short i = 0; i < crtTotalSize; i++) {
                isValid &= (buffer[bLen++] == crts[i]);
            }
            if (!isValid)
                ISOException.throwIt(SW_CERT_VERIFICATION_FAILURE);

            Util.arrayCopy(buffer, bLen, secretOCE, _0, (short) secretOCE.length);
        }
        else {
            // The buffer contains the signature, we append all data to hash at the end
            bLen = in_received;
            buffer[bLen++] = (byte) 0xD3;
            buffer[bLen++] = (byte) 0x01;
            buffer[bLen++] = sessionSecurityLvl;
            bLen = Util.arrayCopy(crts, _0, buffer, bLen, crtTotalSize);
            bLen = Util.arrayCopy(challenge, _0, buffer, bLen, (short) challenge.length);

            if (!currentPublicKey_sig.VerifyPKCS1(buffer, in_received, (short) (bLen-in_received), _0))
                ISOException.throwIt(SW_CERT_VERIFICATION_FAILURE);
        }

        if (keyExchangeMode == KEY_TRANSPORT_ID) {
            setSuccessfulCommunication(_0);
        }
    }

    /**
     * Get the challenge sent by OCE and sign it.
     * For key transport, a simple PKCS1v1.5 signature of the challenge is done.
     * For key agreement, a secret is generated and a signature with message
     * recovery is performed. The signature is encrypted with OCE's public key.
     * @return
     *      Length of the signature
     */
    private short internalAuthenticate() {
        if (in_received != (short) (challengeLen + CERTIFICATE_ID_LENGTH)) {
            ISOException.throwIt((short) (SW_DATA_INCOMPLETE + challengeLen + CERTIFICATE_ID_LENGTH - in_received));
        }

        Util.arrayCopyNonAtomic(buffer, _0, challenge, _0, challengeLen);
        Util.arrayCopy(currentID_sig, _0, buffer, in_received, CERTIFICATE_ID_LENGTH);
        if (Utils.CompareConstantTime(buffer, challengeLen, in_received) != 0)
            ISOException.throwIt(SW_INCORRECT_VALUES);

        if (keyExchangeMode == KEY_AGREEMENT_ID) {
            short paddLen = (short) (sdKey_sig.modulusSizeByte - 22 - secretSD.length);
            // We leave enough memory at the beginning of buffer to store the
            // signature, and store the payload to sign after
            bLen = sdKey_sig.modulusSizeByte;
            rng.generateData(buffer, sdKey_sig.modulusSizeByte, paddLen);
            bLen += paddLen;
            rng.generateData(secretSD, _0, (short) secretSD.length);
            bLen = Util.arrayCopy(secretSD, _0, buffer, bLen, (short) secretSD.length);
            bLen = Util.arrayCopy(challenge, _0, buffer, bLen, challengeLen);
            bLen = Util.arrayCopy(currentID_sig, _0, buffer, bLen, CERTIFICATE_ID_LENGTH);

            // Compute the signature
            bLen = sdKey_sig.SignWithMessageRecovery(buffer, sdKey_sig.modulusSizeByte,
                    (short) (bLen- sdKey_sig.modulusSizeByte), sdKey_sig.modulusSizeByte,
                    (short) (paddLen+secretSD.length), buffer, _0);

            // Encrypt it with OCE's public key
            bLen = currentPublicKey_enc.publicKeyOperation(buffer, _0, bLen, Cipher.MODE_DECRYPT);
        }
        else {
            // Set up the buffer to SessionKey || challenge and sign
            short crtOff = 0;
            bLen = 0;
            for (short i = 0; i < nbCrts; i++) {
                bLen += CRTJC.getKey(crts, crtOffsets[i], buffer, bLen);
            }
            bLen = Util.arrayCopy(challenge, _0, buffer, bLen, challengeLen);
            bLen = sdKey_sig.SignPKCS1(buffer, _0, bLen, _0);
        }

        setSuccessfulCommunication(bLen);

        return bLen;
    }

    /**
     * Set some instance variable (security level, ...) and compute the session
     * and the IV in case of key agreement.
     * @param bOffset
     *      Offset of buffer from which we can write without overwriting returned
     *      data.
     */
    private void setSuccessfulCommunication(short bOffset) {
        this.currentSecurityLvl = this.sessionSecurityLvl;
        // TODO Derive the key from secrets
    }

    /**
     * Provide support for command chaining by storing the received data in
     * buffer
     * @param apdu
     *      Current APDU.
     */
    private void commandChaining(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short p1p2 = Util.makeShort(buf[OFFSET_P1], buf[OFFSET_P2]);
        short len = (short) (buf[OFFSET_LC] & 0xFF);

        // Reset chaining if it was not yet initiated
        if (!chain) {
            resetChaining();
        }

        if ((byte) (buf[OFFSET_CLA] & (byte) 0x10) == (byte) 0x10) {
            // If chaining was already initiated, INS and P1P2 should match
            if (chain && (buf[OFFSET_INS] != chain_ins || p1p2 != chain_p1p2)) {
                resetChaining();
                ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            }

            // Check whether data to be received is larger than size of the
            // buffer
            if ((short) (in_received + len) > BUFFER_MAX_LENGTH) {
                resetChaining();
                ISOException.throwIt(SW_WRONG_DATA);
            }

            // Store received data in buffer
            in_received = Util.arrayCopyNonAtomic(buf, OFFSET_CDATA,
                    buffer, in_received, len);

            chain = true;
            chain_ins = buf[OFFSET_INS];
            chain_p1p2 = p1p2;

            ISOException.throwIt(SW_NO_ERROR);
        }

        if (chain && buf[OFFSET_INS] == chain_ins && p1p2 == chain_p1p2) {
            chain = false;

            // Check whether data to be received is larger than size of the
            // buffer
            if ((short) (in_received + len) > BUFFER_MAX_LENGTH) {
                resetChaining();
                ISOException.throwIt(SW_WRONG_DATA);
            }

            // Add received data to the buffer
            in_received = Util.arrayCopyNonAtomic(buf, OFFSET_CDATA,
                    buffer, in_received, len);
        } else if (chain) {
            // Chained command expected
            resetChaining();
            ISOException.throwIt(SW_UNKNOWN);
        } else {
            // No chaining was used, so copy data to buffer
            in_received = Util.arrayCopyNonAtomic(buf, OFFSET_CDATA,
                    buffer, _0, len);
        }
    }

    private void resetChaining() {
        chain = false;
        in_received = 0;
    }

    /**
     * Send len bytes from buffer. If len is greater than RESPONSE_MAX_LENGTH,
     * remaining data can be retrieved using GET RESPONSE.
     *
     * @param apdu
     *      Current APDU.
     * @param len
     *      The byte length of the data to send
     */
    private void sendBuffer(APDU apdu, short len) {
        out_sent = 0;
        out_left = len;
        sendNext(apdu);
    }

    /**
     * Send provided status
     * @param apdu
     *      Current APDU.
     * @param status
     *      Status to send
     */
    private void sendException(APDU apdu, short status) {
        resetInstanceVariables();
        terminated = true;

        sendNext(apdu, status);
    }

    /**
     * Send next block of data in buffer. Used for sending data in <buffer>
     * @param apdu
     *      Current APDU.
     */
    private void sendNext(APDU apdu) {
        sendNext(apdu, SW_NO_ERROR);
    }

    /**
     * Send next block of data in buffer. Used for sending data in <buffer>
     * @param apdu
     *      Current APDU.
     * @param status
     *      Status to send
     */
    private void sendNext(APDU apdu, short status) {
        byte[] buf = apdu.getBuffer();
        apdu.setOutgoing();

        // Determine maximum size of the messages
        short max_length = (RESPONSE_MAX_LENGTH > out_left) ? out_left : RESPONSE_MAX_LENGTH;
        Util.arrayCopyNonAtomic(buffer, out_sent, buf, _0, max_length);

        short len = out_left;
        if (out_left > max_length) {
            len = max_length;

            // Compute byte left and sent
            out_left -= max_length;
            out_sent += max_length;

            // Determine new status word
            if (out_left > max_length) {
                status = (short) (SW_BYTES_REMAINING_00 | max_length);
            } else {
                status = (short) (SW_BYTES_REMAINING_00 | out_left);
            }
        } else {
            // Reset buffer
            out_sent = 0;
            out_left = 0;
        }

        // Send data in buffer
        apdu.setOutgoingLength(len);
        apdu.sendBytes(_0, len);

        // Send status word
        if (status != SW_NO_ERROR)
            ISOException.throwIt(status);
    }

}
