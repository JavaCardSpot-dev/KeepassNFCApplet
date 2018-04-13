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
	public String passwordKeyString;
	public boolean useDefaultKey;
	public String testDataString;
	public List<String> command = new ArrayList<>();

	public byte[] TEST_PASSWORD_KEY = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
	public byte[] TEST_INPUT = {(byte)0x70, (byte)0x65, (byte)0x72, (byte)0x73, (byte)0x69,
			(byte)0x6d, (byte)0x6d, (byte)0x6f, (byte)0x6e, (byte)0x73, (byte)0x20, (byte)0x2d, (byte)0x20,
			(byte)0x79, (byte)0x75, (byte)0x6d};

	public byte[] passwordKey;
	public byte[] passwordKeyIv;
	public byte[] testData;
	private SecureRandom random;

	public final static byte CLA_CARD_KPNFC_CMD = (byte)0xB0;

	public final static byte INS_CARD_GET_CARD_PUBKEY = (byte)0x70;
	public final static byte INS_CARD_SET_PASSWORD_KEY = (byte)0x71;
	public final static byte INS_CARD_PREPARE_DECRYPTION = (byte)0x72;
	public final static byte INS_CARD_DECRYPT_BLOCK = (byte)0x73;
	public final static byte INS_CARD_GET_VERSION = (byte)0x74;
	public final static byte INS_CARD_GENERATE_CARD_KEY = (byte)0x75;
	public final static byte INS_CARD_WRITE_TO_SCRATCH = (byte)0x76;

	public final static byte RESPONSE_SUCCEEDED = (byte)0x1;
	public final static byte RESPONSE_FAILED = (byte)0x2;

	public static final byte OFFSET_CLA = 0x00;
	public static final byte OFFSET_INS = 0x01;
	public static final byte OFFSET_P1 = 0x02;
	public static final byte OFFSET_P2 = 0x03;
	public static final byte OFFSET_LC = 0x04;
	public static final byte OFFSET_DATA = 0x05;
	public static final byte HEADER_LENGTH = 0x05;

	// AID of the KPNFC decryptor: f0 37 54 72  80 4f d5 fa  0f 24 3e 42  c1 b6 38 25
	public void run() throws CardException
	{
		if (command.size() == 0) {
			System.err.println("Specify a command.");
			return;
		}

		random = new SecureRandom();

		passwordKey = new byte[16];

		if (useDefaultKey) {
			System.arraycopy(TEST_PASSWORD_KEY, 0, passwordKey, 0, passwordKey.length);
		} else {
			if (passwordKeyString != null) {
				passwordKey = decodeHexString(passwordKeyString);
			} else {
				passwordKey = randomBytes(16);
				//System.out.println("Chose random password key: " + toHex(passwordKey));
			}
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
					setPasswordKey();
					break;
				case "encrypt":
					encrypt();
					break;
				case "decrypt":
					decrypt();
					break;
				case "version":
					version();
					break;
				default:
					System.err.println("Unknown command '" + cmd + "'");
					break;
			}
		}
	}

	public void generateCardKey() throws CardException
	{
		byte[] command = constructApdu(INS_CARD_GENERATE_CARD_KEY);

		sendSingleCommand(command);
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

		if (result == null || result[0] != 1) {
			System.err.println("Couldn't retrieve exponent");
			return null;
		}

		BigInteger exponent = new BigInteger(1, Arrays.copyOfRange(result, 3, result[2] + 3));

		List<byte[]> modulusPortions = new ArrayList<>();
		args[0] = 2; // get modulus
		short offset = 0, bytesToGo = 0;
		do {
			putShort(args, 1, offset);
			command = constructApdu(INS_CARD_GET_CARD_PUBKEY, args);
			result = sendAPDU(channel, command).getBytes();

			if (result == null || result[0] != 1) {
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

	public void setPasswordKey() throws CardException
	{
		CardChannel channel = getCardChannel();
		if (channel == null) {
			return;
		}
		byte[] encryptedPasswordKey = encryptWithCardKey(channel, passwordKey);
		if (encryptedPasswordKey == null) {
			return;
		}

		writeToScratchArea(channel, encryptedPasswordKey);

		byte[] command = constructApdu(INS_CARD_SET_PASSWORD_KEY);
		sendAPDU(channel, command);
		System.out.println("Password key set to " + toHex(passwordKey));
	}

	private byte[] sendSingleCommand(byte[] command) throws CardException
	{
		CardChannel channel = getCardChannel();
		if (channel != null) {
			ResponseAPDU response = sendAPDU(channel, command);
			return response.getBytes();
		} else {
			return null;
		}
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

	public void encrypt()
	{
		/* Encrypts test data with the password key for testing. */
		Cipher cipher;

		try {
			cipher = Cipher.getInstance("AES/CBC/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
			return;
		}

		SecretKeySpec key = new SecretKeySpec(passwordKey, "AES");
		IvParameterSpec iv = new IvParameterSpec(passwordKeyIv);
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			return;
		}

		byte[] result;
		try {
			result = cipher.doFinal(TEST_INPUT);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return;
		}

		System.out.println("Original:  " + toHex(TEST_INPUT));
		System.out.println("IV:        " + toHex(passwordKeyIv));
		System.out.println("Encrypted: " + toHex(result));
	}

	public byte[] randomBytes(int count)
	{
		byte[] theBytes = new byte[count];
		random.nextBytes(theBytes);
		return theBytes;
	}

	public void decrypt() throws CardException
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
				return;
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
			apdu = constructApdu(INS_CARD_DECRYPT_BLOCK, testData);
			ResponseAPDU response = sendAPDU(channel, apdu);

			// This is encrypted with the transaction key, so decrypt it.
			byte[] decrypted = decryptWithTransactionKey(response.getBytes(), 1, 16, transactionKey, transactionIv);
			if (decrypted != null) {
				for (byte b : decrypted) {
					System.out.print(Integer.toHexString(b & 0xff) + ' ');
				}
				System.out.println();
			}
		}
	}

	public void version() throws CardException
	{
		byte[] nullPayload = {};
		byte[] command = constructApdu(INS_CARD_GET_VERSION, nullPayload);

		byte[] response = sendSingleCommand(command);

		if (response != null) {
			System.out.println("Applet version " + response[1]);
		}
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

	public static byte[] constructApdu(byte command)
	{
		byte[] nothing = {};
		return constructApdu(command, nothing);
	}

	public static byte[] constructApdu(byte command, byte[] data)
	{
		byte[] apdu = new byte[HEADER_LENGTH + data.length];
		apdu[OFFSET_CLA] = CLA_CARD_KPNFC_CMD;
		apdu[OFFSET_INS] = command;
		apdu[OFFSET_P1] = (byte)0;
		apdu[OFFSET_P2] = (byte)0;
		apdu[OFFSET_LC] = (byte)data.length;

		System.arraycopy(data, 0, apdu, OFFSET_DATA, data.length);

		return apdu;
	}

	abstract public CardChannel getCardChannel() throws CardException;

	abstract public CardChannel getNewCardChannel() throws CardException;

	abstract public CardTerminal getFirstCardTerminal() throws CardException;

	public ResponseAPDU sendAPDU(CardChannel channel, byte[] apdu) throws CardException {
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
