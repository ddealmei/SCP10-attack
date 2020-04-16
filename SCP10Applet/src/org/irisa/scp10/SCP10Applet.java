package org.irisa.scp10;

/*
 * THIS IMPLEMENTATIONS CONTAINS VULNERABILITIES AND SHOULD NOT BE USED IN PRODUCTION
 */

import javacard.framework.*;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class SCP10Applet extends Applet implements ISO7816 {
    private static final short _0 = 0;

    private static short BUFFER_MAX_LENGTH = 519;
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
    static private RSAKeyHolderJC sdKey;
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

    static private byte[] sdCert = {127, 78, -127, -75, 95, 41, 1, 0, 66, 8, 70,
            82, 84, 80, 48, 48, 48, 49, 127, 73, -127, -122, -127, -127, -128,
            -87, 3, -83, 75, -101, 26, -118, -25, -111, 21, -125, -31, -117,
            -124, -30, -19, 24, -38, -67, -17, 63, -5, -101, -116, 65, -59, 125,
            -59, 115, 67, 83, -68, 30, 42, 97, 47, -35, 102, 127, -26, -121,
            -26, 54, -38, 107, 15, 120, 104, 61, -83, 89, 81, 111, 100, -83,
            -32, 67, -47, -116, 30, 52, 109, 4, 113, 124, 26, 102, 125, 78, 59,
            -8, -66, -1, 111, 0, -55, -92, -114, -97, 94, -116, 88, -48, 49, 78,
            103, -109, 65, 11, 19, -114, 93, 31, 61, 87, -98, 21, 21, -114,
            -109, 118, -58, 121, -8, -17, 66, 103, -21, -121, -113, -113, 83,
            102, 124, -62, 13, 122, 90, 8, -109, 35, 4, 71, 104, 122, -110, 25,
            89, -126, 1, 3, 95, 32, 8, 70, 82, 79, 67, 69, 48, 48, 50, 95, 37,
            6, 1, 9, 1, 0, 2, 3, 95, 36, 6, 6, 9, 0, 8, 1, 3, 95, 55, -127,
            -128, 59, 59, 49, 51, -36, -38, 113, -75, -6, 4, 3, -53, 12, 106,
            -41, 124, -66, -127, 15, -23, 40, 34, 93, -78, 90, -66, -85, -4, 54,
            67, -32, -95, 41, 8, -82, -74, -92, -97, -8, -112, 106, 19, -17, 40,
            30, -122, -60, 117, -28, 82, 81, 91, -55, 35, -19, -39, -117, 96,
            -11, 65, -9, 91, -98, -14, 86, -56, 53, -89, -17, -64, 7, -54, -72,
            -114, -114, -71, -6, 112, -1, 3, -9, -121, -98, -22, -67, 91, -86,
            -28, 56, -112, 39, 104, -38, 126, -111, 84, -10, -18, 2, 63, 94, -7,
            -28, 117, -62, 79, -1, 18, -118, 26, 34, -124, 41, -59, 76, -98, 85,
            -95, -53, 99, 45, 49, -58, 34, -54, -89, -35, -109};
    static private RSAKeyHolderJC defaultPublicKey;
    static private RSAKeyHolderJC sessionPublicKey;

    // Instance variables
    private RandomData rng; // FIXME replace this with a more secure alternative (cf. https://stackoverflow.com/questions/15749186/generate-random-number-bounded-between-two-numbers-in-java-card/15762598)

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

    private RSAKeyHolderJC currentPublicKey;
    private byte[] currentID;

    private boolean chain = false;
    private byte chain_ins = 0;
    private short chain_p1p2 = 0;

    private byte[] buffer;
    private short out_left = 0;
    private short out_sent = 0;
    private short in_received = 0;

    private short nbCrts;
    private short[] crtOffsets;
    private byte[] crts;

    private short bLen = 0;

    private SCP10Applet(byte[] bArray, short bOffset, byte bLength) {
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        // Set SD key
        sdKey = new RSAKeyHolderJC((short) 1024);
        CertificateJC.setRSAPublicKey(sdCert, (short) 4, (short) (sdCert.length-4), sdKey);
        byte[] key = {(byte) 0xDD, (byte) 0xF5, (byte) 0x54, (byte) 0x29, (byte) 0x24, (byte) 0x39, (byte) 0xF6, (byte) 0x99, (byte) 0x30, (byte) 0x01, (byte) 0xD1, (byte) 0xC0, (byte) 0x1D, (byte) 0xA3, (byte) 0x96, (byte) 0x12, (byte) 0x3A, (byte) 0xFC, (byte) 0x63, (byte) 0xD5, (byte) 0x34, (byte) 0x01, (byte) 0x83, (byte) 0x20, (byte) 0x2D, (byte) 0xA4, (byte) 0xCE, (byte) 0x13, (byte) 0xE1, (byte) 0xD6, (byte) 0xC6, (byte) 0x29, (byte) 0xBE, (byte) 0xE4, (byte) 0x34, (byte) 0x5B, (byte) 0x67, (byte) 0x59, (byte) 0x14, (byte) 0xB1, (byte) 0xC4, (byte) 0x3C, (byte) 0x18, (byte) 0x57, (byte) 0x00, (byte) 0x0B, (byte) 0x17, (byte) 0x0E, (byte) 0x79, (byte) 0xD5, (byte) 0x44, (byte) 0x57, (byte) 0x5D, (byte) 0x92, (byte) 0xCC, (byte) 0x31, (byte) 0x6B, (byte) 0xE1, (byte) 0x28, (byte) 0xFA, (byte) 0x24, (byte) 0x43, (byte) 0xFD, (byte) 0x0B, (byte) 0xC2, (byte) 0xEF, (byte) 0xA0, (byte) 0xDF, (byte) 0x34, (byte) 0xFB, (byte) 0x5D, (byte) 0x32, (byte) 0x24, (byte) 0xC7, (byte) 0x0F, (byte) 0x24, (byte) 0x68, (byte) 0x91, (byte) 0x4F, (byte) 0xA7, (byte) 0xEA, (byte) 0xA5, (byte) 0x0D, (byte) 0x24, (byte) 0x7C, (byte) 0xED, (byte) 0x41, (byte) 0x33, (byte) 0xDE, (byte) 0x06, (byte) 0xCC, (byte) 0x3B, (byte) 0x2D, (byte) 0xCA, (byte) 0xF5, (byte) 0xA2, (byte) 0x18, (byte) 0xFD, (byte) 0xC3, (byte) 0x6C, (byte) 0x18, (byte) 0x05, (byte) 0xEC, (byte) 0x34, (byte) 0x02, (byte) 0xBE, (byte) 0xC4, (byte) 0xE7, (byte) 0xA3, (byte) 0x2C, (byte) 0xBE, (byte) 0x3B, (byte) 0x8A, (byte) 0x10, (byte) 0x38, (byte) 0xA8, (byte) 0xE7, (byte) 0x27, (byte) 0xCE, (byte) 0xDD, (byte) 0x45, (byte) 0x0C, (byte) 0x27, (byte) 0xA1, (byte) 0xAB, (byte) 0x96, (byte) 0x19, (byte) 0xAB, (byte) 0x93, (byte) 0xF8, (byte) 0xE2, (byte) 0xC6, (byte) 0x18, (byte) 0x26, (byte) 0xA4, (byte) 0x66, (byte) 0x20, (byte) 0x01, (byte) 0x36, (byte) 0x80, (byte) 0x13, (byte) 0xC2, (byte) 0x64, (byte) 0x0C, (byte) 0x27, (byte) 0x52, (byte) 0xED, (byte) 0x38, (byte) 0xCD, (byte) 0x56, (byte) 0x57, (byte) 0x6A, (byte) 0xC9, (byte) 0x18, (byte) 0x89, (byte) 0x62, (byte) 0x96, (byte) 0x8F, (byte) 0x2E, (byte) 0xC6, (byte) 0x7F, (byte) 0x42, (byte) 0xCD, (byte) 0x92, (byte) 0x44, (byte) 0xE6, (byte) 0x0D, (byte) 0xCB, (byte) 0xD8, (byte) 0x28, (byte) 0x10, (byte) 0x3A, (byte) 0x00, (byte) 0x07, (byte) 0x64, (byte) 0xB4, (byte) 0x51, (byte) 0x38, (byte) 0xD8, (byte) 0x3A, (byte) 0x3E, (byte) 0x61, (byte) 0xDD, (byte) 0x76, (byte) 0x47, (byte) 0xEB, (byte) 0x70, (byte) 0xA6, (byte) 0xC2, (byte) 0xD7, (byte) 0xFE, (byte) 0x07, (byte) 0x81, (byte) 0xF5, (byte) 0x15, (byte) 0xEA, (byte) 0x23, (byte) 0x52, (byte) 0x3E, (byte) 0x21, (byte) 0x6D, (byte) 0xDA, (byte) 0x0A, (byte) 0x18, (byte) 0x45, (byte) 0xB6, (byte) 0x35, (byte) 0x1A, (byte) 0x9C, (byte) 0x6E, (byte) 0x08, (byte) 0xC2, (byte) 0xFD, (byte) 0xF3, (byte) 0x80, (byte) 0xCD, (byte) 0x3E, (byte) 0xAF, (byte) 0x32, (byte) 0xD2, (byte) 0x1E, (byte) 0x87, (byte) 0x4E, (byte) 0x6C, (byte) 0x10, (byte) 0xA9, (byte) 0x2C, (byte) 0xF2, (byte) 0xBA, (byte) 0xAE, (byte) 0x9D, (byte) 0x78, (byte) 0x01, (byte) 0xD4, (byte) 0x83, (byte) 0x45, (byte) 0x17, (byte) 0x73, (byte) 0x29, (byte) 0x7D, (byte) 0x06, (byte) 0xB5, (byte) 0x7B, (byte) 0x1B, (byte) 0x44, (byte) 0xC5, (byte) 0x34, (byte) 0x93, (byte) 0x83, (byte) 0x5D, (byte) 0x6F, (byte) 0xC1, (byte) 0x1D, (byte) 0x0E, (byte) 0xBB, (byte) 0xC7, (byte) 0x4B, (byte) 0x88, (byte) 0x00, (byte) 0xF1, (byte) 0x84, (byte) 0xE1, (byte) 0x2E, (byte) 0x90, (byte) 0x6B, (byte) 0x92, (byte) 0xE6, (byte) 0x07, (byte) 0x0A, (byte) 0xA0, (byte) 0xAA, (byte) 0x3A, (byte) 0xEC, (byte) 0x30, (byte) 0xCC, (byte) 0xEA, (byte) 0x07, (byte) 0xE9, (byte) 0xBB, (byte) 0x55, (byte) 0x6D, (byte) 0x58, (byte) 0x37, (byte) 0x56, (byte) 0x18, (byte) 0x2C, (byte) 0x63, (byte) 0xFC, (byte) 0x0F, (byte) 0xC1, (byte) 0xE3, (byte) 0xAE, (byte) 0x77, (byte) 0xC8, (byte) 0x29, (byte) 0x5D, (byte) 0x92, (byte) 0xA1, (byte) 0xD3, (byte) 0x0A, (byte) 0x6F, (byte) 0x6A, (byte) 0xF0, (byte) 0xD7, (byte) 0x8A, (byte) 0xC5, (byte) 0x7F, (byte) 0x3F, (byte) 0x89, (byte) 0x0E, (byte) 0xE0, (byte) 0x7B, (byte) 0x11, (byte) 0xA6, (byte) 0x07, (byte) 0x40, (byte) 0xBD, (byte) 0x5A, (byte) 0x2E, (byte) 0xD6};
        sdKey.setPrivateKey(key, _0, (short) 64, (short) 64, (short) 64, (short) 128, (short) 64, (short) 192, (short) 64, (short) 256, (short) 64);

        // Init Trust Point public key
        defaultPublicKey = new RSAKeyHolderJC((short) 1024);
        CertificateJC.setRSAPublicKey(trustPointCert, (short) 4, (short) (trustPointCert.length-4), defaultPublicKey);

        /* Init an other public key, to store OCE public key if its exponent or
         * modulus size differ from the default key size.
         * We need to do so because the buffer storing e and n in the public key
         * object are not properly resize,, and their actual size is used during
         * public key operation.
         * For instance going from e = 0x10001 to e = 0x10 will cause e to be
         * read as 0x10000
         */
        sessionPublicKey = new RSAKeyHolderJC((short) 1024);

        // Init buffers
        buffer = JCSystem.makeTransientByteArray(BUFFER_MAX_LENGTH,
                JCSystem.CLEAR_ON_DESELECT);
        challenge = JCSystem.makeTransientByteArray((short) 16,
                JCSystem.CLEAR_ON_DESELECT);
        secretOCE = JCSystem.makeTransientByteArray((short) 32,
                JCSystem.CLEAR_ON_DESELECT);
        secretSD = JCSystem.makeTransientByteArray((short) 32,
                JCSystem.CLEAR_ON_DESELECT);
        crts = JCSystem.makeTransientByteArray((short) (CRTJC.MAX_CRT_SIZE*5),
                JCSystem.CLEAR_ON_DESELECT);

        crtOffsets = new short[5];
        currentID = new byte[CERTIFICATE_ID_LENGTH];

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

        // Set the current public key to Trust Point public key
        currentPublicKey = defaultPublicKey;
        CertificateJC.getHolderRef(trustPointCert, (short) 4, (short) (trustPointCert.length-4), currentID, _0);
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
            // TODO: Public key and private key references, maybe TLV encoded
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
            bLen = CertificateJC.encodeCVC(sdCert, _0, (short) sdCert.length, buffer, _0);
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
        // Check if we have a CVC object
        if (Util.getShort(buffer, _0) != CertificateJC.CVC_TAG)
            ISOException.throwIt(SW_INCORRECT_VALUES);
        bLen = CertificateJC.getCertificateBody(buffer, (short) 5, (short) (in_received-5), buffer, in_received);

        // Get the issuer of the certificate, and check if it is TrustPoint
        CertificateJC.getIssuerRef(buffer, in_received, bLen, buffer, (short) (in_received+bLen));
        Util.arrayCopy(currentID, _0, buffer, (short) (in_received+bLen+CERTIFICATE_ID_LENGTH), CERTIFICATE_ID_LENGTH);
        if (Utils.CompareConstantTime(buffer, (short) (in_received+bLen), (short) (in_received+bLen+CERTIFICATE_ID_LENGTH)) != 0)
            ISOException.throwIt(SW_CERT_VERIFICATION_FAILURE);

        // Check the signature
        CertificateJC.getSignature(buffer, (short) 5, (short) (in_received-5), buffer, _0);
        if (!currentPublicKey.VerifyPKCS1(buffer, in_received, bLen, _0)) {
            ISOException.throwIt(SW_CERT_VERIFICATION_FAILURE);
        }

        currentPublicKey = sessionPublicKey;
        CertificateJC.setRSAPublicKey(buffer, in_received, bLen, currentPublicKey);
        CertificateJC.getHolderRef(buffer, in_received, bLen, currentID, _0);

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
            bLen = sdKey.DecryptPKCS1Deterministic(buffer, _0, in_received);

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
            // If an error occurred during the general process, return a unique error, as mentionned in the specification
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
            bLen = sdKey.privateKeyOperation(buffer, _0, in_received);

            // Append the additional data to buffer (challenge and card id)
            Util.arrayCopy(challenge, _0, buffer, bLen, challengeLen);
            CertificateJC.getHolderRef(sdCert, _0, (short) sdCert.length, buffer, (short) (bLen + challengeLen));

            // Recovered data will be stored after the signature and the additional data
            short recoveredOffset = (short) (bLen+ challengeLen + CERTIFICATE_ID_LENGTH);

            if (!currentPublicKey.VerifyWithMessageRecovery(buffer, _0, bLen,
                    bLen, (short) (challengeLen +CERTIFICATE_ID_LENGTH), buffer,
                    recoveredOffset))
                ISOException.throwIt(SW_CERT_VERIFICATION_FAILURE);

            // Check recovered data format
            // size_n(128) - secret(32) - hash(20) - sig_pad(2) - security_tlv(3) - crt
            short paddLen = (short) (sdKey.modulusSizeByte - secretOCE.length - 20 - 2 - 3 - crtTotalSize);
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

            if (!currentPublicKey.VerifyPKCS1(buffer, in_received, (short) (bLen-in_received), _0))
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
        Util.arrayCopy(currentID, _0, buffer, in_received, CERTIFICATE_ID_LENGTH);
        if (Utils.CompareConstantTime(buffer, challengeLen, in_received) != 0)
            ISOException.throwIt(SW_INCORRECT_VALUES);

        if (keyExchangeMode == KEY_AGREEMENT_ID) {
            short paddLen = (short) (sdKey.modulusSizeByte - 22 - secretSD.length);
            // We leave enough memory at the beginning of buffer to store the
            // signature, and store the payload to sign after
            bLen = sdKey.modulusSizeByte;
            rng.generateData(buffer, sdKey.modulusSizeByte, paddLen);
            bLen += paddLen;
            rng.generateData(secretSD, _0, (short) secretSD.length);
            bLen = Util.arrayCopy(secretSD, _0, buffer, bLen, (short) secretSD.length);
            bLen = Util.arrayCopy(challenge, _0, buffer, bLen, challengeLen);
            bLen = Util.arrayCopy(currentID, _0, buffer, bLen, CERTIFICATE_ID_LENGTH);

            // Compute the signature
            bLen = sdKey.SignWithMessageRecovery(buffer, sdKey.modulusSizeByte,
                    (short) (bLen-sdKey.modulusSizeByte), sdKey.modulusSizeByte,
                    (short) (paddLen+secretSD.length), buffer, _0);

            // Encrypt it with OCE's public key
            bLen = currentPublicKey.publicKeyOperation(buffer, _0, bLen, Cipher.MODE_DECRYPT);
        }
        else {
            // Set up the buffer to SessionKey || challenge and sign
            short crtOff = 0;
            bLen = 0;
            for (short i = 0; i < nbCrts; i++) {
                bLen += CRTJC.getKey(crts, crtOffsets[i], buffer, bLen);
            }
            bLen = Util.arrayCopy(challenge, _0, buffer, bLen, challengeLen);
            bLen = sdKey.SignPKCS1(buffer, _0, bLen, _0);
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
