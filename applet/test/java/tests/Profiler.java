package tests;

import cardTools.RunConfig;
import net.lardcave.keepassnfcapplet.KeepassNFC;
import org.junit.Assert;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class Profiler {
	private CardToolsClient client;
	private RSAPublicKey key = null;
	private ResponseAPDU lastResponse = null;

	private int numberOfRetries = 10;

	private Profiler(String[] args)
	{
		client = new CardToolsClient(KeepassNFC.class, "F0375472804FD5FA0F243E42C1B63825");
		client.setThrowOnCommandException(true);
		client.setCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
		// client.setCardType(RunConfig.CARD_TYPE.PHYSICAL);
		client.setbDebug(false);
		if (args.length > 0) {
			if (Integer.parseInt(args[0]) > 0) {
				numberOfRetries = Integer.parseInt(args[0]);
			}
		}
	}

	public static void main(String[] args) throws Exception
	{
		Profiler profiler = new Profiler(args);
		profiler.profile();
	}

	private interface Measurer {
		long measure() throws Exception;
	}

	private void profileOne(final String code, final String name, final Measurer fun) throws Exception
	{
		long measurements = 0L;
		System.out.println();
		System.out.printf("[%s]", name);
		System.out.println();
		for (int i = 0; i < numberOfRetries; ++i) {
			long t = fun.measure();
			if (t != -1L) {
				measurements += t;
				System.out.printf("%d, ", t);
			} else
				--i;
		}
		System.out.println();
		System.out.printf("[%s] %s takes: %d ms (average of %d measurements)",
				code, name, measurements / numberOfRetries, numberOfRetries);
		System.out.println();
	}

	private interface MeasurerBool {
		boolean measure() throws Exception;
	}

	private void profileOne(final String code, final String name, final MeasurerBool fun) throws Exception
	{
		profileOne(code, name, new Measurer() {
			@Override
			public long measure() throws Exception
			{
				return fun.measure() ?
						client.getCardMngr().getLastTransmitTime() : -1L;
			}
		});
	}

	private interface MeasurerVoid {
		void measure() throws Exception;
	}

	private void profileOne(final String code, final String name, final MeasurerVoid fun) throws Exception
	{
		profileOne(code, name, new Measurer() {
			@Override
			public long measure() throws Exception
			{
				fun.measure();
				return client.getCardMngr().getLastTransmitTime();
			}
		});
	}

	private void profile() throws Exception
	{
		final byte[] userPIN = new byte[]{0x31, 0x32, 0x33, 0x34};
		final byte[] masterPIN = new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
		client.installSelectApplet();

		// class 90
		profileOne("9072", "Get Lock reason", new MeasurerBool() {
			@Override
			public boolean measure() throws Exception
			{
				return client.getLockReason().length >= 2;
			}
		});
		profileOne("9074", "Get Version", new MeasurerBool() {
			@Override
			public boolean measure() throws Exception
			{
				return client.getVersion() > 0;
			}
		});


		// class A0
		profileOne("A080", "Verify Master PIN", new MeasurerBool() {
			@Override
			public boolean measure() throws Exception
			{
				return client.verifyMasterPIN(masterPIN);
			}
		});
		profileOne("A081", "Set Master PIN", new MeasurerBool() {
			@Override
			public boolean measure() throws Exception
			{
				return client.verifyMasterPIN(masterPIN) && client.setMasterPIN(masterPIN);
			}
		});
		profileOne("A082", "Verify User PIN", new MeasurerBool() {
			@Override
			public boolean measure() throws Exception
			{
				return client.verifyUserPIN(userPIN);
			}
		});
		profileOne("A083", "Set User PIN", new MeasurerBool() {
			@Override
			public boolean measure() throws Exception
			{
				return client.verifyMasterPIN(masterPIN) && client.setUserPIN(userPIN);
			}
		});


		// class B0
		client.verifyUserPIN(userPIN);
		profileOne("B075", "Card Key generation", new Measurer() {
			@Override
			public long measure() throws Exception
			{
				return generateCardKey();
			}
		});
		profileOne("B070_01", "Get Card Key public exponent", new Measurer() {
			@Override
			public long measure() throws Exception
			{
				return getCardKeyExp();
			}
		});
		profileOne("B070_02", "Get Card Key public modulus (first call)", new Measurer() {
			@Override
			public long measure() throws Exception
			{
				return getCardKeyMod1();
			}
		});
		profileOne("B071", "Password Key set", new Measurer() {
			@Override
			public long measure() throws Exception
			{
				return setPasswordKey();
			}
		});
		profileOne("B072", "Transaction Key set", new Measurer() {
			@Override
			public long measure() throws Exception
			{
				return setTransactionKey();
			}
		});
		profileOne("B073", "128 bytes block decrypt", new Measurer() {
			@Override
			public long measure() throws Exception
			{
				return decryptBlock();
			}
		});
		final byte[] data16 = "TestDataCorrectL".getBytes();
		profileOne("B076", "Write to Scratch 16 bytes", new MeasurerVoid() {
			@Override
			public void measure() throws Exception
			{
				client.writeToScratchArea(client.getCardChannel(), data16);
			}
		});
		final byte[] data32 = "TestDataCorrectLengthThats32Byte".getBytes();
		profileOne("B076", "Write to Scratch 32 bytes", new MeasurerVoid() {
			@Override
			public void measure() throws Exception
			{
				client.writeToScratchArea(client.getCardChannel(), data32);
			}
		});
		final byte[] data64 = "TestDataCorrectLengthThats32ByteTestDataCorrectLengthThats32Byte".getBytes();
		profileOne("B076", "Write to Scratch 64 bytes", new MeasurerVoid() {
			@Override
			public void measure() throws Exception
			{
				client.writeToScratchArea(client.getCardChannel(), data64);
			}
		});
	}

	private long generateCardKey() throws CardException
	{
		byte[] command = client.constructApdu(client.INS_CARD_GENERATE_CARD_KEY);
		lastResponse = client.sendAPDU(command);
		long time = client.getCardMngr().getLastTransmitTime();
		if (lastResponse.getData().length == 3 && lastResponse.getData()[0] == client.RESPONSE_SUCCEEDED) {
			key = client.getCardPubKey(client.getCardChannel());
			return time;
		}
		return -1L;
	}

	private long getCardKeyExp() throws Exception
	{
		byte[] args = new byte[3];

		args[0] = 1; // get exponent
		args[1] = 0;
		args[2] = 0;
		byte[] command = client.constructApdu(client.INS_CARD_GET_CARD_PUBKEY, args);
		byte[] result = client.sendAPDU(command).getBytes();

		if (result == null || result[0] != client.RESPONSE_SUCCEEDED) {
			System.err.println("Couldn't retrieve exponent");
			return -1L;
		}
		return client.getCardMngr().getLastTransmitTime();
	}

	private long getCardKeyMod1() throws Exception
	{
		byte[] args = new byte[3];

		args[0] = 2; // get modulus
		args[1] = 0;
		args[2] = 0;
		byte[] command = client.constructApdu(client.INS_CARD_GET_CARD_PUBKEY, args);
		byte[] result = client.sendAPDU(command).getBytes();

		if (result == null || result[0] != client.RESPONSE_SUCCEEDED) {
			System.err.println("Couldn't retrieve exponent");
			return -1L;
		}
		return client.getCardMngr().getLastTransmitTime();
	}

	private long setPasswordKey() throws Exception
	{
		if (key == null)
			generateCardKey();
		byte[] passwordKey = client.randomBytes(client.AES_LEN / 8);
		byte[] encryptedPasswordKey = client.encryptWithCardKey(client.getCardChannel(), passwordKey);
		if (encryptedPasswordKey == null) {
			return -1L;
		}

		client.writeToScratchArea(client.getCardChannel(), encryptedPasswordKey);

		byte[] command = client.constructApdu(client.INS_CARD_SET_PASSWORD_KEY);
		lastResponse = client.sendAPDU(command);
		long time = client.getCardMngr().getLastTransmitTime();
		if (lastResponse.getData()[0] == client.RESPONSE_SUCCEEDED) {
			// System.out.println("Password key set to " + client.toHex(passwordKey));
			return time;
		}
		return -1L;
	}

	private long setTransactionKey() throws Exception
	{
		if (key == null)
			generateCardKey();
		client.setNewPasswordKey();
		client.setPasswordKeyIv();

		// Generate a random transaction key and IV.
		byte[] transactionKey = client.randomBytes(16);
		byte[] transactionIv = client.randomBytes(16);

		// Connect to the card and establish a transaction key.
		byte[] transactionParameters = new byte[32];

		// Prepare decryption: 16 bytes of transaction key, encrypted with the card key,
		// followed by two IVs.
		byte[] encryptedTransactionKey = client.encryptWithCardKey(client.getCardChannel(), transactionKey);
		if (encryptedTransactionKey == null) {
			return -1L;
		}
		// The encrypted transaction key is too large (256 bytes for a 2048-bit RSA key) to fit
		// in one APDU, so write it to the card's scratch area in pieces.
		client.writeToScratchArea(client.getCardChannel(), encryptedTransactionKey);

		// Now that the encrypted key is in the scratch area, tell the card to decrypt the
		// transaction key and prepare for decryption using the password key.
		System.arraycopy(transactionIv, 0, transactionParameters, 0, 16);
		System.arraycopy(client.passwordKeyIv, 0, transactionParameters, 16, 16);
		ResponseAPDU response = client.sendAPDU(client.constructApdu(client.INS_CARD_PREPARE_DECRYPTION, transactionParameters));
		long time = client.getCardMngr().getLastTransmitTime();
		if (response.getData()[0] == 1)
			return time;
		return -1L;
	}

	private long decryptBlock() throws CardException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException
	{
		if (key == null)
			generateCardKey();
		client.setNewPasswordKey();
		client.setPasswordKeyIv();
		byte[] data = "TestDataCorrectLengthThats32ByteTestDataCorrectLengthThats32ByteTestDataCorrectLengthThats32ByteTestDataCorrectLengthThats32Byte".getBytes();
		byte[] encryptedData = client.encrypt(data);

		// Generate a random transaction key and IV.
		byte[] transactionKey = client.randomBytes(16);
		byte[] transactionIv = client.randomBytes(16);

		// Connect to the card and establish a transaction key.
		byte[] apdu;
		byte[] transactionParameters = new byte[32];

		// Prepare decryption: 16 bytes of transaction key, encrypted with the card key,
		// followed by two IVs.
		byte[] encryptedTransactionKey = client.encryptWithCardKey(client.getCardChannel(), transactionKey);
		if (encryptedTransactionKey == null) {
			return -1L;
		}
		// The encrypted transaction key is too large (256 bytes for a 2048-bit RSA key) to fit
		// in one APDU, so write it to the card's scratch area in pieces.
		client.writeToScratchArea(client.getCardChannel(), encryptedTransactionKey);

		// Now that the encrypted key is in the scratch area, tell the card to decrypt the
		// transaction key and prepare for decryption using the password key.
		System.arraycopy(transactionIv, 0, transactionParameters, 0, 16);
		System.arraycopy(client.passwordKeyIv, 0, transactionParameters, 16, 16);
		client.sendAPDU(client.constructApdu(client.INS_CARD_PREPARE_DECRYPTION, transactionParameters));

		// Decryption has been initialised, so ask the card to decrypt the text.
		apdu = client.constructApdu(client.INS_CARD_DECRYPT_BLOCK, encryptedData);
		lastResponse = client.sendAPDU(apdu);
		long time = client.getCardMngr().getLastTransmitTime();
		ResponseAPDU response = lastResponse;

		// This is encrypted with the transaction key, so decrypt it.
		byte[] decrypted = client.decryptWithTransactionKey(response.getData(), 1, response.getData().length - 1, transactionKey, transactionIv);
		Assert.assertTrue(Arrays.equals(data, decrypted));
		return time;
	}
}
