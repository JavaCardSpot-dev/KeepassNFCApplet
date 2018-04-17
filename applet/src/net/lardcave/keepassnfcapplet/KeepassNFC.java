// This source code describes KeepassNFC applet which will interact with user to decrypt his encrypted database
// The applet currently provides decryption of already encrypted database which user will send to app for decryption

package net.lardcave.keepassnfcapplet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

// TODO: encrypt-then-MAC: http://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac

public class KeepassNFC extends Applet {
	final static byte CLA_CARD_KPNFC_CMD           = (byte)0xB0;   // class identification of the card being used for applet

	final static byte INS_CARD_GET_CARD_PUBKEY     = (byte)0x70;   // Instruction to get card public key
	final static byte INS_CARD_SET_PASSWORD_KEY    = (byte)0x71;   // Instruction to set password key
	final static byte INS_CARD_PREPARE_DECRYPTION  = (byte)0x72;   // Instruction for PKI safe share the AES decryption
	final static byte INS_CARD_DECRYPT_BLOCK       = (byte)0x73;
	final static byte INS_CARD_GET_VERSION         = (byte)0x74;   // instruction to get version
	final static byte INS_CARD_GENERATE_CARD_KEY   = (byte)0x75;
	final static byte INS_CARD_WRITE_TO_SCRATCH    = (byte)0x76;

	final static byte RESPONSE_SUCCEEDED           = (byte)0x1;      // response byte for success
	final static byte RESPONSE_FAILED              = (byte)0x2;      // response for failure
	final static short RESPONSE_STATUS_OFFSET      = ISO7816.OFFSET_CDATA;	//offset defined as per ISO7816 standards

	final static byte VERSION                      = (byte)0x1;

	final static short SW_CRYPTO_EXCEPTION         = (short)0xF100;

	final static byte RSA_ALGORITHM                = KeyPair.ALG_RSA_CRT;    // genrtaion of key pair using RSA algorithm
	final static short RSA_KEYLENGTH               = KeyBuilder.LENGTH_RSA_2048;   // RSA key length 2048

	// Definining the variables
	private KeyPair card_key = null;
	private AESKey password_key = null;
	private AESKey transaction_key = null;

	private Cipher card_cipher = null;
	private Cipher password_cipher = null;
	private Cipher transaction_cipher = null;

	private byte[] scratch_area = null;    // space to store the keys or data at different times during encryption/decryption
	private byte[] aes_key_temporary = null;

	//method to generate the three keys
	protected KeepassNFC(byte[] bArray, short bOffset, byte bLength)
	{
		// Generating RSA Key pair
		card_key = new KeyPair(RSA_ALGORITHM, RSA_KEYLENGTH);
		// AES -128 Bit Passowrd Key
		password_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		// AES -128 Bit Transaction key
		transaction_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);

		card_cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		password_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		transaction_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

		scratch_area = JCSystem.makeTransientByteArray((short)260, JCSystem.CLEAR_ON_DESELECT);
		aes_key_temporary = JCSystem.makeTransientByteArray((short)260, JCSystem.CLEAR_ON_DESELECT);

		cleanAllSensitiveData();
		register();
	}

	// method to install the applet
	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
	{
		new KeepassNFC(bArray, bOffset, bLength);
	}

	private void cleanTransientSensitiveData() {
		transaction_key.clearKey();
		// card_cipher
		// password_cipher
		// transaction_cipher
		Util.arrayFillNonAtomic(scratch_area, (short)0, (short)scratch_area.length, (byte)0);
		Util.arrayFillNonAtomic(aes_key_temporary, (short)0, (short)aes_key_temporary.length, (byte)0);
	}

	private void cleanAllSensitiveData() {
		password_key.clearKey();
		card_key.getPrivate().clearKey();
		cleanTransientSensitiveData();
		card_key.getPublic().clearKey();
	}

	// method to select the applet
	public boolean select()
	{
		cleanTransientSensitiveData();
		return true;
	}

	public void deselect()
	{
		cleanTransientSensitiveData();
	}

	// method to process APDU from client
	public void process(APDU apdu) throws ISOException
	{
		byte[] buffer = apdu.getBuffer();   // buffer for holding the header

		if (selectingApplet())
			return;

		if (buffer[ISO7816.OFFSET_CLA] == CLA_CARD_KPNFC_CMD) {   // checking CLA field of header
			switch (buffer[ISO7816.OFFSET_INS]) {
				case INS_CARD_GET_CARD_PUBKEY:    // Getting the card public key
					getCardPubKey(apdu);
					break;
				case INS_CARD_SET_PASSWORD_KEY:   // setting the password key
					setPasswordKey(apdu);
					break;
				case INS_CARD_PREPARE_DECRYPTION:    //to exchange safely the AES keys for decryption via PKI system
					prepareDecryption(apdu);
					break;
				case INS_CARD_DECRYPT_BLOCK:   // decryption of database
					decryptBlock(apdu);
					break;
				case INS_CARD_GET_VERSION:   // getting the version
					getVersion(apdu);
					break;
				case INS_CARD_GENERATE_CARD_KEY:  // generating the card keys
					generateCardKey(apdu);
					break;
				case INS_CARD_WRITE_TO_SCRATCH:    //APDU instruction to write in the scratch area
					writeToScratch(apdu);
					break;
				default:
					ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
					break;
			}
		} else if (buffer[ISO7816.OFFSET_CLA] != CLA_CARD_KPNFC_CMD) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
	}

	private static final short PUBKEY_MAX_SEND_LENGTH = 120;
	private static final byte PUBKEY_GET_EXPONENT = 1;
	private static final byte PUBKEY_GET_MODULUS = 2;
	private static final short PUBKEY_REQUEST_OFFSET_IDX = (short)(ISO7816.OFFSET_CDATA + 1);
	private static final short PUBKEY_RESPONSE_EXPONENT_OFFSET = (short)3;
	private static final short PUBKEY_RESPONSE_MODULUS_OFFSET = (short)5;
	private static final short PUBKEY_RESPONSE_LENGTH_IDX = (short)(ISO7816.OFFSET_CDATA + 1);
	private static final short PUBKEY_RESPONSE_REMAIN_IDX = (short)(ISO7816.OFFSET_CDATA + 3);
	private static final short PUBKEY_RESPONSE_EXPONENT_IDX = (short)(ISO7816.OFFSET_CDATA + PUBKEY_RESPONSE_EXPONENT_OFFSET);
	private static final short PUBKEY_RESPONSE_MODULUS_IDX = (short)(ISO7816.OFFSET_CDATA + PUBKEY_RESPONSE_MODULUS_OFFSET);

	/**
	 * Method to send Public Key (exponent & modulus) to the user application.
	 * <p>
	 * response APDU (for exponent request):
	 * * 1 byte: RESPONSE_SUCCEEDED
	 * * 2 bytes: length of exponent
	 * * n bytes: exponent (up to 4 bytes)
	 * response APDU (for modulus request):
	 * * 1 byte: REPONSE_SUCCEEDED
	 * * 2 bytes: number of bytes sent this time
	 * * 2 bytes: bytes remaining to send
	 * * n bytes: modulus (up to MAX_PUBKEY_SEND_LENGTH bytes)
	 * response APDU (in case of wrong input data):
	 * * SW: SW_WRONG_LENGTH (0x6700) or SW_WRONG_DATA(0x6A80)
	 * response APDU (in case of crypto errors):
	 * * SW: SW_CRYPTO_EXCEPTION (0xF100)
	 * response APDU (in case of unrecognized request type):
	 * * 1 byte: RESPONSE_FAILED
	 *
	 * @param apdu Request APDU formatted this way:
	 *             * 1 byte: type of request -- PUBKEY_GET_EXPONENT or PUBKEY_GET_MODULUS
	 *             * 2 bytes: start byte (if requesting modulus-continue) or 00 00 (otherwise)
	 */
	protected void getCardPubKey(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();   // buffer to hold the header
		short length = apdu.setIncomingAndReceive();
		if (length != (short)3)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if ((short)-length != (short)-3)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		short lengthOut = (short)1;
		byte command = buffer[ISO7816.OFFSET_CDATA];
		short offset = Util.getShort(buffer, PUBKEY_REQUEST_OFFSET_IDX);
		short ret_key_length = (short)0;
		// default to FAILED to manage errors more easily
		buffer[RESPONSE_STATUS_OFFSET] = RESPONSE_FAILED;
		try {
			if (command == PUBKEY_GET_EXPONENT) {
				// getting public key exponent

				if (offset != (short)0)
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);

				RSAPublicKey key = (RSAPublicKey)card_key.getPublic();
				if (!key.isInitialized())
					ISOException.throwIt(SW_CRYPTO_EXCEPTION);
				ret_key_length = key.getExponent(buffer, PUBKEY_RESPONSE_EXPONENT_IDX);
				// prevent Fault Induction on key.getExponent
				if (ret_key_length == (short)0) // don't need second FI check, too near
					ISOException.throwIt(SW_CRYPTO_EXCEPTION);

				Util.setShort(buffer, PUBKEY_RESPONSE_LENGTH_IDX, ret_key_length);
				buffer[RESPONSE_STATUS_OFFSET] = RESPONSE_SUCCEEDED;
				lengthOut = (short)(ret_key_length + PUBKEY_RESPONSE_EXPONENT_OFFSET);
				// Fault Induction prevention, to prevent sending unknown buffer data
				lengthOut = (short)(ret_key_length + PUBKEY_RESPONSE_EXPONENT_OFFSET);
			} else if (command == PUBKEY_GET_MODULUS) { //getting the modulus
				// Always rewrite public modulus in scratch buffer, prevents reading of arbitrary scratch_area positions
				RSAPublicKey key = (RSAPublicKey)card_key.getPublic();
				if (!key.isInitialized())
					ISOException.throwIt(SW_CRYPTO_EXCEPTION);
				ret_key_length = key.getModulus(scratch_area, (short)0);
				// prevent Fault Induction on key.getModulus
				if (ret_key_length == (short)0) // don't need second FI check, too near
					ISOException.throwIt(SW_CRYPTO_EXCEPTION);

				// calculating the length of key
				short amountToSend = (short)(ret_key_length - offset);

				// clamp amountToSend between 0 and maximum buffer length.
				if (amountToSend > PUBKEY_MAX_SEND_LENGTH)
					if ((short)-amountToSend < (short)-PUBKEY_MAX_SEND_LENGTH) // Fault Induction check
						amountToSend = PUBKEY_MAX_SEND_LENGTH;
				if (amountToSend < 0)
					if ((short)-amountToSend > 0) // Fault Induction check
						amountToSend = 0;

				Util.arrayCopy(scratch_area, offset, buffer, PUBKEY_RESPONSE_MODULUS_IDX, amountToSend);

				buffer[RESPONSE_STATUS_OFFSET] = RESPONSE_SUCCEEDED;
				Util.setShort(buffer, PUBKEY_RESPONSE_LENGTH_IDX, amountToSend);
				Util.setShort(buffer, PUBKEY_RESPONSE_REMAIN_IDX, (short)(ret_key_length - offset - amountToSend));
				lengthOut = (short)(amountToSend + PUBKEY_RESPONSE_MODULUS_OFFSET);
				// Fault Induction prevention, to prevent sending unknown buffer data
				lengthOut = (short)(amountToSend + PUBKEY_RESPONSE_MODULUS_OFFSET);
			} // else nothing has changed: lengthOut == 1, RESPONSE_FAILED
		} catch (CryptoException e) {
			ISOException.throwIt((short)(SW_CRYPTO_EXCEPTION | e.getReason()));
		}
		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, lengthOut);
	}

	/**
	 * Method to share AES password key required for decryption of database.
	 * <p>
	 * This method assumes that the client has alrady written its Password Key,
	 * encrypted with the Card Key, to the scratch area (with 0x76, writeToScratch instruction).
	 * This is assumed to be long RSA_KEYLENGTH / 8.
	 * <p>
	 * response APDU (in case of correct storage of Password Kay):
	 * * 1 byte: RESPONSE_SUCCEEDED
	 * response APDU (in case of provided input):
	 * * SW: SW_WRONG_LENGTH (0x6700)
	 * response APDU (in case of decrypt error):
	 * * SW: SW_CONDITIONS_NOT_SATISFIED (0x6985)
	 *
	 * @param apdu Request APDU, empty.
	 */
	protected void setPasswordKey(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();
		// check that length of incoming data is 0, with fault induction prevention
		if (length == (short)0)
			if ((short)-length == (short)0) {
				decryptWithCardKey(scratch_area, (short)0, password_key);
				buffer[RESPONSE_STATUS_OFFSET] = RESPONSE_SUCCEEDED;
				apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
				ISOException.throwIt(ISO7816.SW_NO_ERROR);
			}
		buffer[RESPONSE_STATUS_OFFSET] = RESPONSE_FAILED;
		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}


	/**
	 * Decrypt the transaction key and set up AES engines for decryption.
	 * <p>
	 * This method assumes that the client has alrady configured the card
	 * with its Password Key.
	 * <p>
	 * This method assumes that the client has alrady written its Transaction Key,
	 * encrypted with the Card Key, to the scratch area (with 0x76, writeToScratch instruction).
	 * This is assumed to be long RSA_KEYLENGTH / 8.
	 * <p>
	 * response APDU (in case of correct storage of Password Kay):
	 * * 1 byte: RESPONSE_SUCCEEDED
	 * response APDU (in case of incorrect length of provided input):
	 * * SW: SW_WRONG_LENGTH (0x6700)
	 * response APDU (in case of crypto error):
	 * * SW: SW_CONDITIONS_NOT_SATISFIED (0x6985)
	 *
	 * @param apdu Request APDU formatted this way:
	 *             * 16 bytes: IV for transaction key (plaintext)
	 *             * 16 bytes: IV for password key (plaintext)
	 */
	protected void prepareDecryption(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();
		// check that length of incoming data is 32, with fault induction prevention
		if (length == 32)
			if ((short)-length == (short)-32) {
				decryptWithCardKey(scratch_area, (short)0, transaction_key);
				try { // catch crypto exceptions
					transaction_cipher.init(transaction_key, Cipher.MODE_ENCRYPT, buffer, (short)(ISO7816.OFFSET_CDATA + 0), (short)16);
					password_cipher.init(password_key, Cipher.MODE_DECRYPT, buffer, (short)(ISO7816.OFFSET_CDATA + 16), (short)16);
				} catch (CryptoException e) {
					// cleanup sensitive data
					transaction_key.clearKey();
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
				buffer[RESPONSE_STATUS_OFFSET] = RESPONSE_SUCCEEDED;
				apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
				ISOException.throwIt(ISO7816.SW_NO_ERROR);
			}
		buffer[RESPONSE_STATUS_OFFSET] = RESPONSE_FAILED;
		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	/**
	 * Decrypt a block of the database.
	 *
	 * response APDU (in case of correct decryption):
	 * * 1 byte: RESPONSE_SUCCEEDED
	 * * n bytes: decrypted block, encrypted with Transaction Key
	 * response APDU (in case of crypto error):
	 * * 1 byte: RESPONSE_FAILED
	 *
	 * @param apdu Request APDU containing encrypted data, already padded.
	 *             If P1 contains 0x80, the block is considered to be the last.
	 */
	protected void decryptBlock(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();

		short encrypted = 0;
		try {
			short decrypted = 0;
			if ((buffer[ISO7816.OFFSET_P1] & 0x80) != 0) {    // Not last block;
				decrypted = password_cipher.update(buffer, (short)ISO7816.OFFSET_CDATA, length, scratch_area, (short)0);
			} else {                                          // Last block;
				decrypted = password_cipher.doFinal(buffer, (short)ISO7816.OFFSET_CDATA, length, scratch_area, (short)0);
			}
			// default to failed status, so only if everything is good it is set to RESPONSE_SUCCEEDED
			buffer[RESPONSE_STATUS_OFFSET] = RESPONSE_FAILED;
			if (decrypted > 0) {
				if ((short)-decrypted < (short)0) { // Fault induction check
					/* We decrypted the blocks successfully, now re-encrypt with the transaction key. */
					if ((buffer[ISO7816.OFFSET_P1] & 0x80) != 0) {    // Not last block;
						encrypted = transaction_cipher.update(scratch_area, (short)0, decrypted, buffer, (short)(RESPONSE_STATUS_OFFSET + 1));
					} else {                                          // Last block;
						encrypted = transaction_cipher.doFinal(scratch_area, (short)0, decrypted, buffer, (short)(RESPONSE_STATUS_OFFSET + 1));
					}
					if (encrypted > 0) {
						if ((short)-encrypted < (short)0) { // Fault induction check
							/* We encrypted the new block successfully. */
							buffer[RESPONSE_STATUS_OFFSET] = RESPONSE_SUCCEEDED;
						} else {
							encrypted = 0;
						}
					} else {
						encrypted = 0;
					}
				}
			}
		} catch (CryptoException | ArrayIndexOutOfBoundsException e) {
			buffer[RESPONSE_STATUS_OFFSET] = RESPONSE_FAILED;
			encrypted = 0;
		} finally {
			// cleanup sensitive data, with fault induction prevention
			Util.arrayFillNonAtomic(scratch_area, (short)0, (short)scratch_area.length, (byte)0);
			Util.arrayFillNonAtomic(scratch_area, (short)0, (short)scratch_area.length, (byte)0);
		}

		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)(encrypted + 1));
	}

	protected void getVersion(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();

		buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;
		buffer[ISO7816.OFFSET_CDATA + 1] = VERSION;
		// sending the version of Applet
		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)2);
	}

	/**
	 * Method to generate a new Card Key pair.
	 * <p>
	 * response APDU (in case of correct generation):
	 * * 1 byte: RESPONSE_SUCCEEDED
	 * * 2 bytes: Key length (bits)
	 * response APDU (in case of provided input):
	 * * SW: SW_WRONG_LENGTH (0x6700)
	 * response APDU (in case of crypto error):
	 * * SW: 0xF100 | e.getReason() (INVALID_INIT in case of keys not initialized after genKeyPair())
	 *
	 * @param apdu Request APDU, empty.
	 */
	protected void generateCardKey(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();

		if (length != (short)0) {
			buffer[RESPONSE_STATUS_OFFSET] = RESPONSE_FAILED;
			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		try {
			card_key.genKeyPair();
		} catch (CryptoException e) {
			card_key.getPrivate().clearKey();
			card_key.getPublic().clearKey();
			ISOException.throwIt((short)(SW_CRYPTO_EXCEPTION | e.getReason()));
		}

		// checking card keys are generated correctly or not
		if (card_key.getPublic().isInitialized() && card_key.getPrivate().isInitialized()) {
			buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;
			Util.setShort(buffer, (short)(ISO7816.OFFSET_CDATA + 1), RSA_KEYLENGTH);
			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)3);
		} else {
			buffer[ISO7816.OFFSET_CDATA] = RESPONSE_FAILED;
			apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
			ISOException.throwIt((short)(SW_CRYPTO_EXCEPTION | CryptoException.INVALID_INIT));
		}
	}

	/**
	 * Save raw data to scratch area. This data is then used by other functions.
	 * <p>
	 * response APDU (in case of correct storage of Password Kay):
	 * * 1 byte: RESPONSE_SUCCEEDED
	 * * 2 bytes: amount of free space after saved data
	 * response APDU (in case of incorrect length of provided input):
	 * * SW: SW_WRONG_LENGTH (0x6700)
	 *
	 * @param apdu Request APDU formatted this way:
	 *             * 2 bytes: offset from which to write in scratch
	 *             * n bytes: actual data
	 */
	protected void writeToScratch(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();

		short offset = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		// check the data length fits into the scratch area, prevent fault induction
		if ((short)scratch_area.length >= (short)(offset + length - 2)) {
			if ((short)(scratch_area.length + 2) >= (short)(offset + length)) {
				Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA + 2), scratch_area, offset, (short)(length - 2));
				buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;
				Util.setShort(buffer, (short)(ISO7816.OFFSET_CDATA + 1), (short)(scratch_area.length - offset - length + 2));
				apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)3);
				ISOException.throwIt(ISO7816.SW_NO_ERROR);
			}
		}
		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	/**
	 * Method to decrypt the AES keys which are encrypted with Card Public key and have been sent by the client to the applet.
	 *
	 * @param input  Input byte array containing encrypted key.
	 * @param offset Offset from which the encrypted key starts.
	 * @param output Output byte array where to save decrypted key.
	 * @return Length of decrypted key.
	 */
	private short decryptWithCardKey(byte[] input, short offset, AESKey output)
	{
		// throw error on invalid array length
		if ((short)(input.length - offset) < (short)(RSA_KEYLENGTH / 8))
			ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH | 0x01));
		if ((short)(aes_key_temporary.length) < (short)(RSA_KEYLENGTH / 8))
			ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH | 0x02));

		short decryptedBytes = 0;
		try { // catch crypto exceptions
			// getting the private key
			RSAPrivateCrtKey private_key = (RSAPrivateCrtKey)card_key.getPrivate();
			// initialising the cipher
			card_cipher.init(private_key, Cipher.MODE_DECRYPT);
			// performing the decryption
			decryptedBytes = card_cipher.doFinal(input, offset, (short)(RSA_KEYLENGTH / 8), aes_key_temporary, (short)0);
			if (decryptedBytes == (short)0)
				throw new CryptoException(CryptoException.ILLEGAL_USE);
			output.setKey(aes_key_temporary, (short)0);
			if (!output.isInitialized())
				throw new CryptoException(CryptoException.INVALID_INIT);
		} catch (CryptoException e) {
			// cleanup sensitive data, with fault induction prevention
			Util.arrayFillNonAtomic(aes_key_temporary, (short)0, (short)aes_key_temporary.length, (byte)0);
			Util.arrayFillNonAtomic(aes_key_temporary, (short)0, (short)aes_key_temporary.length, (byte)0);
			output.clearKey();
			decryptedBytes = 0;
			throw e;
		} finally {
			// cleanup sensitive data, with fault induction prevention
			Util.arrayFillNonAtomic(aes_key_temporary, (short)0, (short)aes_key_temporary.length, (byte)0);
			Util.arrayFillNonAtomic(aes_key_temporary, (short)0, (short)aes_key_temporary.length, (byte)0);
		}
		return decryptedBytes;
	}
}
