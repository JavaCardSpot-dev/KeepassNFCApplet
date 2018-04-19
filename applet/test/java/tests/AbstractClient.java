package tests;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@SuppressWarnings({"WeakerAccess", "Duplicates"})
abstract public class AbstractClient {
	public boolean useDefaultKey;
	public String testDataString;
	public List<String> command = new ArrayList<>();

	public byte[] TEST_PASSWORD_KEY = {31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16,
			15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
	public byte[] TEST_INPUT = {(byte)0x70, (byte)0x65, (byte)0x72, (byte)0x73, (byte)0x69,
			(byte)0x6d, (byte)0x6d, (byte)0x6f, (byte)0x6e, (byte)0x73, (byte)0x20, (byte)0x2d, (byte)0x20,
			(byte)0x79, (byte)0x75, (byte)0x6d};

	public byte[] passwordKey;
	public byte[] passwordKeyIv;
	public byte[] testData;
	private SecureRandom random;

	public final static byte CLA_CARD_KPNFC_CMD = (byte)0xB0;
	public final static byte CLA_CARD_KPNFC_PIN = (byte)0xA0;
	public final static byte CLA_CARD_KPNFC_ALL = (byte)0x90;

	public final static byte INS_CARD_GET_CARD_PUBKEY = (byte)0x70;
	public final static byte INS_CARD_SET_PASSWORD_KEY = (byte)0x71;
	public final static byte INS_CARD_PREPARE_DECRYPTION = (byte)0x72;
	public final static byte INS_CARD_DECRYPT_BLOCK = (byte)0x73;
	public final static byte INS_CARD_GET_VERSION = (byte)0x74;
	public final static byte INS_CARD_GENERATE_CARD_KEY = (byte)0x75;
	public final static byte INS_CARD_WRITE_TO_SCRATCH = (byte)0x76;
	public final static byte INS_VERIFY_MASTER_PIN = (byte)0x80;
	public final static byte INS_SET_MASTER_PIN = (byte)0x81;
	public final static byte INS_VERIFY_USER_PIN = (byte)0x82;
	public final static byte INS_SET_USER_PIN = (byte)0x83;
	public final static byte RESPONSE_SUCCEEDED = (byte)0x1;
	public final static byte RESPONSE_FAILED = (byte)0x2;

	public static final byte OFFSET_CLA = 0x00;
	public static final byte OFFSET_INS = 0x01;
	public static final byte OFFSET_P1 = 0x02;
	public static final byte OFFSET_P2 = 0x03;
	public static final byte OFFSET_LC = 0x04;
	public static final byte OFFSET_DATA = 0x05;
	public static final byte HEADER_LENGTH = 0x05;

	public static final int AES_LEN = 128;

	AbstractClient()
	{
		random = new SecureRandom();
	}

	// AID of the KPNFC decryptor: f0 37 54 72  80 4f d5 fa  0f 24 3e 42  c1 b6 38 25
	public void run() throws CardException
	{
		if (command.size() == 0) {
			System.err.println("Specify a command.");
			return;
		}

		passwordKeyIv = new byte[16];

		if (testDataString != null)
			testData = decodeHexString(testDataString);

		//System.out.println("You specified data: " + toHex(testData));

		for (String cmd : command) {
			switch (cmd) {
				case "generate_card_key":
					generateCardKey();
					break;
				case "set_password_key":
					setNewPasswordKey();
					break;
				case "encrypt":
					try {
						encrypt();
					} catch (IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
						e.printStackTrace();
					}
					break;
				case "decrypt":
					decrypt(testData);
					break;
				case "version":
					getVersion();
					break;
				default:
					System.err.println("Unknown command '" + cmd + "'");
					break;
			}
		}
	}

	public short generateCardKey() throws CardException
	{
		byte[] command = constructApdu(INS_CARD_GENERATE_CARD_KEY);

		ResponseAPDU keyLength = sendAPDU(command);
		if (keyLength.getData().length == 3 && keyLength.getData()[0] == RESPONSE_SUCCEEDED)
			return getShort(keyLength.getData(), 1); // [RESPONSE_SUCCEEDED, keyLength2Bytes]
		return -1;
	}

	protected short getShort(byte[] buffer, int idx)
	{
		// assumes big-endian which seems to be how JavaCard rolls
		return (short)((((buffer[idx] & 0xff) << 8) | (buffer[idx + 1] & 0xff)));
	}

	protected void putShort(byte[] args, int idx, short val)
	{
		args[idx] = (byte)((val & 0xff) >> 8);
		args[idx + 1] = (byte)(val & 0xff);
	}

	public RSAPublicKey getCardPubKey(CardChannel channel) throws CardException
	{
		byte[] args = new byte[3];

		args[0] = 1; // get exponent
		args[1] = 0;
		args[2] = 0;
		byte[] command = constructApdu(INS_CARD_GET_CARD_PUBKEY, args);
		byte[] result = sendAPDU(channel, command).getBytes();

		if (result == null || result[0] != RESPONSE_SUCCEEDED) {
			System.err.println("Couldn't retrieve exponent");
			return null;
		}

		BigInteger exponent = new BigInteger(1, Arrays.copyOfRange(result, 3, result[2] + 3));

		List<byte[]> modulusPortions = new ArrayList<>();
		args[0] = 2; // get modulus
		short offset = 0, bytesToGo;
		do {
			putShort(args, 1, offset);
			command = constructApdu(INS_CARD_GET_CARD_PUBKEY, args);
			result = sendAPDU(channel, command).getBytes();

			if (result == null || result[0] != RESPONSE_SUCCEEDED) {
				System.err.println("Couldn't retrieve modulus");
				return null;
			}
			int bytesSent = getShort(result, 1);
			bytesToGo = getShort(result, 3);

			modulusPortions.add(Arrays.copyOfRange(result, 5, result.length - 2)); // exclude result code
			offset += bytesSent;
		} while (bytesToGo > 0);

		byte[] modulusBytes = new byte[offset];
		offset = 0;
		for (byte[] portion : modulusPortions) {
			System.arraycopy(portion, 0, modulusBytes, offset, portion.length);
			offset += portion.length;
		}

		BigInteger modulus = new BigInteger(1, modulusBytes);

		// Turn these numbers into a crypto-api-friendly PublicKey object.

		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Couldn't create RSA keyfactory"); // which would be very strange
			return null;
		}

		RSAPublicKey publicKey;
		try {
			publicKey = (RSAPublicKey)keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
		} catch (InvalidKeySpecException e) {
			System.err.println("Couldn't produce a PublicKey object");
			return null;
		}

		return publicKey;
	}

	public static final int MAX_CHUNK_SIZE = 120;

	public void writeToScratchArea(CardChannel channel, byte[] data) throws CardException
	{
		for (int offset = 0; offset < data.length; offset += MAX_CHUNK_SIZE) {
			int amount = data.length - offset;
			if (amount > MAX_CHUNK_SIZE)
				amount = MAX_CHUNK_SIZE;

			byte[] args = new byte[amount + 2];
			putShort(args, 0, (short)offset);

			System.arraycopy(data, offset, args, 2, amount);

			byte[] command = constructApdu(INS_CARD_WRITE_TO_SCRATCH, args);
			sendAPDU(channel, command);
		}
	}

	public boolean setNewPasswordKey(byte[] passwordKey) throws CardException
	{
		this.passwordKey = passwordKey;
		CardChannel channel = getCardChannel();
		if (channel == null) {
			return false;
		}
		byte[] encryptedPasswordKey = encryptWithCardKey(channel, passwordKey);
		if (encryptedPasswordKey == null) {
			return false;
		}

		writeToScratchArea(channel, encryptedPasswordKey);

		byte[] command = constructApdu(INS_CARD_SET_PASSWORD_KEY);
		ResponseAPDU response = sendAPDU(channel, command);
		if (response.getData()[0] == RESPONSE_SUCCEEDED) {
			System.out.println("Password key set to " + toHex(passwordKey));
		}
		return response.getData()[0] == RESPONSE_SUCCEEDED;
	}

	public boolean setNewPasswordKey(String passwordKey) throws CardException
	{
		return setNewPasswordKey(passwordKey.getBytes());
	}

	public boolean setNewPasswordKey() throws CardException
	{
		passwordKey = new byte[AES_LEN / 8];

		if (useDefaultKey) {
			System.arraycopy(TEST_PASSWORD_KEY, 0, passwordKey, 0, AES_LEN / 8);
		} else {
			passwordKey = randomBytes(AES_LEN / 8);
		}
		return setNewPasswordKey(passwordKey);
	}

	public void setPasswordKeyIv(byte[] passwordKeyIv)
	{
		if (passwordKeyIv.length != 16)
			throw new InvalidParameterException("Password Key IV must be 16 bytes long.");
		this.passwordKeyIv = new byte[16];
		System.arraycopy(passwordKeyIv, 0, this.passwordKeyIv, 0, passwordKeyIv.length);
	}

	public void setPasswordKeyIv()
	{
		setPasswordKeyIv(randomBytes(16));
	}

	private byte[] encryptWithCardKey(CardChannel channel, byte[] input) throws CardException
	{
		RSAPublicKey publicKey = getCardPubKey(channel);
		if (publicKey == null) {
			System.err.println("Key invalid, can't encrypt with card key");
			return null;
		}

		Cipher cipher;

		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.err.println("RSA cipher not supported");
			return null;
		}

		try {
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		} catch (InvalidKeyException e) {
			System.err.println("Invalid key");
			return null;
		}

		try {
			return cipher.doFinal(input);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			System.err.println("Couldn't encrypt with card key:");
			e.printStackTrace();
			return null;
		}
	}

	public byte[] encrypt(byte[] input) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException
	{
		/* Encrypts test data with the password key for testing. */
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

		SecretKeySpec key = new SecretKeySpec(passwordKey, "AES");
		IvParameterSpec iv = new IvParameterSpec(passwordKeyIv);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);

		byte[] result;
		result = cipher.doFinal(input);

		System.out.println("Original:  " + toHex(input));
		System.out.println("IV:        " + toHex(passwordKeyIv));
		System.out.println("Encrypted: " + toHex(result));
		return result;
	}

	public byte[] encrypt() throws IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException
	{
		return encrypt(TEST_INPUT);
	}

	public byte[] randomBytes(int count)
	{
		byte[] theBytes = new byte[count];
		random.nextBytes(theBytes);
		return theBytes;
	}

	public byte[] decrypt(byte[] data) throws CardException
	{
		// Generate a random transaction key and IV.
		byte[] transactionKey = randomBytes(16);
		byte[] transactionIv = randomBytes(16);

		// Connect to the card and establish a transaction key.
		byte[] apdu;
		byte[] transactionParameters = new byte[32];

		// Prepare decryption: 16 bytes of transaction key, encrypted with the card key,
		// followed by two IVs.
		CardChannel channel = getCardChannel();

		if (channel != null) {
			byte[] encryptedTransactionKey = encryptWithCardKey(channel, transactionKey);
			if (encryptedTransactionKey == null) {
				return null;
			}
			// The encrypted transaction key is too large (256 bytes for a 2048-bit RSA key) to fit
			// in one APDU, so write it to the card's scratch area in pieces.
			writeToScratchArea(channel, encryptedTransactionKey);

			// Now that the encrypted key is in the scratch area, tell the card to decrypt the
			// transaction key and prepare for decryption using the password key.
			System.arraycopy(transactionIv, 0, transactionParameters, 0, 16);
			System.arraycopy(passwordKeyIv, 0, transactionParameters, 16, 16);
			sendAPDU(channel, constructApdu(INS_CARD_PREPARE_DECRYPTION, transactionParameters));

			// Decryption has been initialised, so ask the card to decrypt the text.
			apdu = constructApdu(INS_CARD_DECRYPT_BLOCK, data);
			ResponseAPDU response = sendAPDU(channel, apdu);

			// This is encrypted with the transaction key, so decrypt it.
			byte[] decrypted = decryptWithTransactionKey(response.getData(), 1, response.getData().length - 1, transactionKey, transactionIv);
			if (decrypted != null) {
				for (byte b : decrypted) {
					System.out.print(Integer.toHexString(b & 0xff) + ' ');
				}
				System.out.println();
			}
			return decrypted;
		}
		return null;
	}

	public byte[] prepareVersionAPDU()
	{
		return constructApdu(CLA_CARD_KPNFC_ALL, INS_CARD_GET_VERSION);
	}

	public byte getVersion() throws CardException
	{
		return getVersion(prepareVersionAPDU());
	}

	public byte getVersion(byte[] command) throws CardException
	{
		byte[] response = sendAPDU(command).getData();

		if (response != null && response.length == 2 && response[0] == RESPONSE_SUCCEEDED) {
			System.out.println("Applet version " + response[1]);
			return response[1];
		}
		throw new CardException("Unknown error");
	}

	public byte[] decryptWithTransactionKey(byte[] source, int start, int length, byte[] keyBytes, byte[] ivBytes)
	{
		Cipher cipher;

		try {
			cipher = Cipher.getInstance("AES/CBC/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
			return null;
		}

		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		try {
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			return null;
		}

		byte[] result;
		try {
			result = cipher.doFinal(source, start, length);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}

		return result;
	}

	public boolean verifyMasterPIN(byte[] masterPIN) throws CardException
	{
		byte[] command = constructApdu(CLA_CARD_KPNFC_PIN, INS_VERIFY_MASTER_PIN, masterPIN);
		byte[] responseData = sendAPDU(command).getData();
		if (responseData != null && responseData.length == 1 && responseData[0] == RESPONSE_SUCCEEDED) {
			return true;
		}
		System.err.println("Master PIN not Matched");
		return false;
	}

	public boolean verifyUserPIN(byte[] userPIN) throws CardException
	{
		byte[] command = constructApdu(CLA_CARD_KPNFC_PIN, INS_VERIFY_USER_PIN, userPIN);
		byte[] responseData = sendAPDU(command).getData();
		if (responseData != null && responseData.length == 1 && responseData[0] == RESPONSE_SUCCEEDED) {
			return true;
		}
		System.err.println("User PIN not Matched");
		return false;
	}

	// set user PIN after verification of master PIN
	public boolean setUserPIN(byte[] userPIN, byte[] masterPIN) throws CardException
	{
		if (verifyMasterPIN(masterPIN))
			return setUserPIN(userPIN);
		return false;
	}

	// set user PIN directly without prior master PIN verification
	public boolean setUserPIN(byte[] userPIN) throws CardException
	{
		byte[] command = constructApdu(CLA_CARD_KPNFC_PIN, INS_SET_USER_PIN, userPIN);
		byte[] responseData = sendAPDU(command).getData();
		if (responseData != null && responseData.length == 1 && responseData[0] == RESPONSE_SUCCEEDED) {
			return true;
		}
		System.err.println("User PIN not set");
		return false;
	}

	// set master PIN after verification of master PIN
	public boolean setMasterPIN(byte[] newMasterPin, byte[] oldMasterPIN) throws CardException
	{
		if (verifyMasterPIN(oldMasterPIN))
			return setMasterPIN(newMasterPin);
		return false;
	}

	// set master PIN directly without prior master PIN verification
	public boolean setMasterPIN(byte[] newMasterPin) throws CardException
	{
		byte[] command = constructApdu(CLA_CARD_KPNFC_PIN, INS_SET_MASTER_PIN, newMasterPin);
		byte[] responseData = sendAPDU(command).getData();
		if (responseData != null && responseData.length == 1 && responseData[0] == RESPONSE_SUCCEEDED) {
			return true;
		}
		System.err.println("Master PIN not set");
		return false;
	}

	public static byte[] constructApdu(byte cla, byte command, byte[] data)
	{
		byte[] apdu = new byte[HEADER_LENGTH + (data == null ? 0 : data.length)];
		apdu[OFFSET_CLA] = cla;
		apdu[OFFSET_INS] = command;
		apdu[OFFSET_P1] = (byte)0;
		apdu[OFFSET_P2] = (byte)0;
		if (data != null) {
			apdu[OFFSET_LC] = (byte)data.length;
			System.arraycopy(data, 0, apdu, OFFSET_DATA, data.length);
		} else {
			apdu[OFFSET_LC] = 0;
		}
		return apdu;
	}

	public static byte[] constructApdu(byte command, byte[] data)
	{
		return constructApdu(CLA_CARD_KPNFC_CMD, command, data);
	}

	public static byte[] constructApdu(byte cla, byte command)
	{
		byte[] nothing = {};
		return constructApdu(cla, command, nothing);
	}

	public static byte[] constructApdu(byte command)
	{
		byte[] nothing = {};
		return constructApdu(command, nothing);
	}

	abstract public CardChannel getCardChannel() throws CardException;

	abstract public CardChannel getNewCardChannel() throws CardException;

	abstract public CardTerminal getFirstCardTerminal() throws CardException;

	public ResponseAPDU sendAPDU(byte[] apdu) throws CardException
	{
		return sendAPDU(getCardChannel(), apdu);
	}

	public ResponseAPDU sendAPDU(CardChannel channel, byte[] apdu) throws CardException
	{
		return sendAPDU(channel, new CommandAPDU(apdu));
	}

	abstract public ResponseAPDU sendAPDU(CardChannel channel, final CommandAPDU apdu) throws CardException;

	public String toHex(byte[] data)
	{
		StringBuilder buf = new StringBuilder();

		for (byte b : data) {
			buf.append(nibbleToChar((byte)((b & 0xff) >> 4))); // java is bs
			buf.append(nibbleToChar((byte)(b & 0xf)));
			buf.append(' ');
		}

		return buf.toString();
	}

	public static char nibbleToChar(byte nibble)
	{
		assert (nibble < 16);

		if (nibble < 10)
			return (char)('0' + nibble);
		else
			return (char)('A' + (nibble - 10));
	}

	public static byte charToNibble(char c)
	{
		if (c >= '0' && c <= '9')
			return (byte)(c - '0');
		if (c >= 'A' && c <= 'F')
			return (byte)(c - 'A' + 10);
		if (c >= 'a' && c <= 'f')
			return (byte)(c - 'a' + 10);

		throw new RuntimeException("Not a hex character");
	}

	public byte[] decodeHexString(String s)
	{
		byte[] decoded = new byte[8]; // initial length

		byte currentByte = 0;
		boolean inNibble = false;
		int index = 0;

		for (char c : s.toCharArray()) {
			if (c == ' ' || c == ':')
				continue;

			currentByte |= charToNibble(c);
			if (inNibble) {
				if (index == decoded.length) {
					// Out of space, so double it.
					byte[] newDecoded = new byte[decoded.length * 2];
					System.arraycopy(decoded, 0, newDecoded, 0, decoded.length);
					decoded = newDecoded;
				}

				// write the completed byte.
				decoded[index] = currentByte;
				index++;
				inNibble = false;
				currentByte = 0;
			} else {
				currentByte <<= 4;
				inNibble = true;
			}
		}

		return Arrays.copyOfRange(decoded, 0, index);
	}

}
