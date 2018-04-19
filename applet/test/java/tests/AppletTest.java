package tests;

import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import javacard.framework.ISO7816;
import net.lardcave.keepassnfcapplet.KeepassNFC;
import org.junit.Assert;
import org.testng.annotations.*;

import javax.crypto.IllegalBlockSizeException;
import javax.smartcardio.CardException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * Test class for KeepassNFC applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author McCio
 */
public class AppletTest {
	final static private RunConfig.CARD_TYPE JCARDSIM = RunConfig.CARD_TYPE.JCARDSIMLOCAL;
	final static private RunConfig.CARD_TYPE PHYSICAL = RunConfig.CARD_TYPE.PHYSICAL;
	protected CardToolsClient client = null;

	public AppletTest()
	{
	}

	// install test first
	@BeforeGroups(groups = {"Installing"})
	public void setUpInstalling() throws Exception
	{
		System.out.println("Setting up client");
		client = new CardToolsClient(KeepassNFC.class, "F0375472804FD5FA0F243E42C1B63825");
		client.setThrowOnCommandException(true);
		client.setCardType(JCARDSIM);
		// client.setCardType(PHYSICAL);
	}

	@AfterGroups(groups = {"Installing"})
	public void tearDownClient() throws Exception
	{
		System.out.println("Disconnecting from client");
		client.getCardMngr().Disconnect(true);
	}

	// Real Install Test
	@Test(groups = {"Installing"})
	public void installTest() throws Exception
	{
		Assert.assertNotNull(client.getCardChannel());
		final CardManager cardMngr = client.installSelectApplet();
		Assert.assertEquals(cardMngr.getAppletId(), client.getAppletAIDByte());
	}

	// initialization before every method after install test
	@BeforeMethod(dependsOnGroups = {"Installing"})
	public void setUpMethod() throws Exception
	{
		setUpInstalling();
		client.installSelectApplet();
	}

	@AfterMethod(dependsOnGroups = {"Installing"})
	public void tearDownMethod() throws Exception
	{
		tearDownClient();
	}

	@Test(dependsOnGroups = {"Installing"})
	public void getVersion() throws Exception
	{
		byte version = client.getVersion();
		Assert.assertEquals((byte)2, version);
	}
	
	@Test(dependsOnGroups = {"Installing"})
	public void getRepo() throws Exception
	{
		byte repo = client.getRepo();
		Assert.assertEquals((byte)53, repo);
	}

	@Test(dependsOnGroups = {"Installing"})
	public void getLockReason() throws Exception
	{
		byte[] reason = client.getLockReason();
		Assert.assertTrue(reason.length >= 2);
	}

	@Test(dependsOnGroups = {"Installing", "PIN"})
	public void getVersion2() throws Exception
	{
		verifyUserPIN();
		byte[] cmd = client.prepareVersionAPDU();
		cmd[client.OFFSET_CLA] = client.CLA_CARD_KPNFC_CMD;
		byte version = client.getVersion(cmd);
		Assert.assertEquals((byte)2, version);
	}

	@Test(dependsOnGroups = {"Installing", "PIN"}, groups = {"Configuring"}, timeOut = 10000)
	public void setupNewCardKey() throws Exception
	{
		verifyUserPIN();
		short keyLength = client.generateCardKey();
		Assert.assertEquals(2048, keyLength);
		RSAPublicKey key = client.getCardPubKey(client.getCardChannel());
		Assert.assertEquals("RSA", key.getAlgorithm());
		Assert.assertEquals("X.509", key.getFormat());
		Assert.assertEquals(2048, key.getModulus().bitLength());
		Assert.assertTrue(key.getPublicExponent().isProbablePrime(10));
	}

	@Test(dependsOnGroups = {"Installing", "PIN"}, groups = {"Failing"})
	public void unverifiedGenerateNewCardKey() throws Exception
	{
		byte[] command = AbstractClient.constructApdu(AbstractClient.CLA_CARD_KPNFC_CMD, AbstractClient.INS_CARD_GENERATE_CARD_KEY);
		assertUnverifiedUserPIN(command);
	}

	@Test(dependsOnGroups = {"Installing", "PIN"}, groups = {"Failing"})
	public void unverifiedGetCardKey() throws Exception
	{
		byte[] command = AbstractClient.constructApdu(AbstractClient.CLA_CARD_KPNFC_CMD, AbstractClient.INS_CARD_GET_CARD_PUBKEY);
		assertUnverifiedUserPIN(command);
	}

	@Test(dependsOnGroups = {"Installing", "PIN"}, groups = {"Failing"})
	public void uninitializedGetCardKeyExponent() throws Exception
	{
		if (client.getCardType() != PHYSICAL) { // in PHYSICAL card no guarantee on uninitialization of Card Key can be given
			verifyUserPIN();
			byte[] command = AbstractClient.constructApdu(AbstractClient.CLA_CARD_KPNFC_CMD, AbstractClient.INS_CARD_GET_CARD_PUBKEY, new byte[]{1, 0, 0});
			assertGeneralCryptoError(command);
		}
	}

	@Test(dependsOnGroups = {"Installing", "PIN"}, groups = {"Failing"})
	public void uninitializedGetCardKeyModulus() throws Exception
	{
		if (client.getCardType() != PHYSICAL) { // in PHYSICAL card no guarantee on uninitialization of Card Key can be given
			verifyUserPIN();
			byte[] command = AbstractClient.constructApdu(AbstractClient.CLA_CARD_KPNFC_CMD, AbstractClient.INS_CARD_GET_CARD_PUBKEY, new byte[]{2, 0, 0});
			assertGeneralCryptoError(command);
		}
	}

	@Test(dependsOnGroups = {"Installing", "PIN"}, groups = {"Failing"})
	public void incorrectOffsetGetCardExponent() throws Exception
	{
		verifyUserPIN();
		byte[] command = AbstractClient.constructApdu(AbstractClient.CLA_CARD_KPNFC_CMD, AbstractClient.INS_CARD_GET_CARD_PUBKEY, new byte[]{1, 0, 1});
		try {
			int response = client.sendAPDU(command).getSW();
			Assert.assertEquals(0x6A80, response);
			if (client.isThrowOnCommandException())
				Assert.fail("Getting Card PubKey Exponent must be done with offset == 0.");
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("6A80"));
		}
	}

	@Test(dependsOnGroups = {"Configuring", "PIN"})
	public void setPasswordKey() throws Exception
	{
		verifyUserPIN();
		client.generateCardKey();
		boolean passwordSet = client.setNewPasswordKey("ASD");
		Assert.assertEquals(true, passwordSet);
	}

	@Test(dependsOnGroups = {"Configuring", "PIN"}, timeOut = 10000)
	public void setDefaultPasswordKey() throws Exception
	{
		verifyUserPIN();
		client.useDefaultKey = true;
		client.generateCardKey();
		boolean passwordSet = client.setNewPasswordKey();
		Assert.assertEquals(true, passwordSet);
	}

	@Test(dependsOnGroups = {"Configuring", "PIN"}, timeOut = 10000)
	public void setRandomPasswordKey() throws Exception
	{
		verifyUserPIN();
		client.generateCardKey();
		boolean passwordSet = client.setNewPasswordKey();
		Assert.assertEquals(true, passwordSet);
	}

	public void assertUnverifiedUserPIN(byte[] command)
	{
		try {
			int response = client.sendAPDU(command).getSW();
			Assert.assertEquals(0x98FF, response | 0xFF);
			if (client.isThrowOnCommandException())
				Assert.fail("Expecting a failure with SW=0x98.. (unverified User PIN)");
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("98"));
		}
	}

	public int assertGeneralCryptoError(byte[] command, String msg)
	{
		int response;
		msg = msg != null ? msg : "Expecting a failure with SW=0xF1.. (CryptoException)";
		try {
			response = client.sendAPDU(command).getSW();
			Assert.assertEquals(0xF1FF, response | 0xFF);
			if (client.isThrowOnCommandException())
				Assert.fail(msg);
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("F1"));
			response = Integer.parseInt(e.getMessage().substring(0, 4), 16);
		}
		return response;
	}

	public int assertGeneralCryptoError(byte[] command)
	{
		return assertGeneralCryptoError(command, null);
	}

	@Test(dependsOnGroups = {"PIN"}, groups = {"Failing"})
	public void unverifiedSetPasswordKey() throws Exception
	{
		byte[] command = AbstractClient.constructApdu(AbstractClient.INS_CARD_SET_PASSWORD_KEY);
		assertUnverifiedUserPIN(command);
	}

	@Test(dependsOnGroups = {"PIN"}, groups = {"Failing"})
	public void unverifiedClassCMD() throws Exception
	{
		byte[] command = AbstractClient.constructApdu(AbstractClient.CLA_CARD_KPNFC_CMD, (byte)0x00);
		assertUnverifiedUserPIN(command);
	}

	@Test(dependsOnGroups = {"Configuring", "PIN"}, timeOut = 10000)
	public void clientEncrypt() throws Exception
	{
		verifyUserPIN();
		client.generateCardKey();
		client.setNewPasswordKey();
		client.setPasswordKeyIv();
		byte[] encrypted = null;
		try {
			encrypted = client.encrypt();
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail("Exception thrown encrypting default data");
		} finally {
			Assert.assertNotNull(encrypted);
		}
		try {
			client.encrypt("Test".getBytes());
		} catch (Exception e) {
			Assert.assertEquals(IllegalBlockSizeException.class, e.getClass());
		}
		encrypted = null;
		try {
			encrypted = client.encrypt("TestDataCorrectL".getBytes());
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail("Exception thrown encrypting default data");
		} finally {
			Assert.assertNotNull(encrypted);
		}
	}

	public void cardDecrypt(byte[] data) throws Exception
	{
		client.generateCardKey();
		client.setNewPasswordKey();
		client.setPasswordKeyIv();
		System.out.print(data.length);
		System.out.println(" bytes to encrypt");
		byte[] encryptedData = client.encrypt(data);
		System.out.print(encryptedData.length);
		System.out.println(" bytes to decrypt");
		byte[] decryptedData = client.decrypt(encryptedData);
		Assert.assertNotNull(decryptedData);
		System.out.println("Prior: " + Util.toHex(data));
		System.out.println("After: " + Util.toHex(decryptedData));
		Assert.assertTrue(Arrays.equals(data, decryptedData));
	}

	@Test(dependsOnGroups = {"PIN"}, groups = {"Failing"})
	public void unverifiedPrepareDecryption() throws Exception
	{
		byte[] command = AbstractClient.constructApdu(AbstractClient.INS_CARD_PREPARE_DECRYPTION);
		assertUnverifiedUserPIN(command);
	}

	@Test(dependsOnGroups = {"Configuring", "PIN"}, groups = {"Failing"})
	public void uninitializedPasswordPrepareDecryption() throws Exception
	{
		verifyUserPIN();
		client.generateCardKey();
		byte[] command = AbstractClient.constructApdu(AbstractClient.INS_CARD_PREPARE_DECRYPTION, new byte[32]);
		assertGeneralCryptoError(command);
	}

	@Test(dependsOnGroups = {"PIN"}, groups = {"Failing"})
	public void unverifiedDecryptBlock() throws Exception
	{
		byte[] command = AbstractClient.constructApdu(AbstractClient.INS_CARD_DECRYPT_BLOCK);
		assertUnverifiedUserPIN(command);
	}

	@Test(dependsOnGroups = {"Configuring", "PIN"}, timeOut = 10000)
	public void cardDecrypt16() throws Exception
	{
		verifyUserPIN();
		cardDecrypt("TestDataCorrectL".getBytes());
	}

	@Test(dependsOnGroups = {"Configuring", "PIN"}, timeOut = 10000)
	public void cardDecrypt32() throws Exception
	{
		verifyUserPIN();
		cardDecrypt("TestDataCorrectLengthThats32Byte".getBytes());
	}

	@Test(dependsOnGroups = {"Configuring", "PIN"}, timeOut = 10000)
	public void cardDecrypt64() throws Exception
	{
		verifyUserPIN();
		cardDecrypt("TestDataCorrectLengthThats32ByteTestDataCorrectLengthThats32Byte".getBytes());
	}

	@Test(groups = {"Failing"})
	public void unsupportedCLA() throws Exception
	{
		try {
			byte[] apdu = AbstractClient.constructApdu((byte)0x00, (byte)0x00);
			Assert.assertEquals(ISO7816.SW_CLA_NOT_SUPPORTED, (short)client.sendAPDU(apdu).getSW());
			if (client.isThrowOnCommandException())
				Assert.fail("Unsupported CLA should throw errors.");
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("6E00"));
		}
	}

	public void unsupportedINS(byte[] apdu) throws Exception
	{
		try {
			Assert.assertEquals(ISO7816.SW_INS_NOT_SUPPORTED, (short)client.sendAPDU(apdu).getSW());
			if (client.isThrowOnCommandException())
				Assert.fail("Unsupported INS should throw errors.");
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("6D00"));
		}
	}

	@Test(groups = {"Failing"})
	public void unsupportedINSall() throws Exception
	{
		byte[] apdu = AbstractClient.constructApdu(AbstractClient.CLA_CARD_KPNFC_ALL, (byte)0x00);
		unsupportedINS(apdu);
	}

	@Test(groups = {"Failing"})
	public void unsupportedINScmd() throws Exception
	{
		byte[] apdu = AbstractClient.constructApdu(AbstractClient.CLA_CARD_KPNFC_CMD, (byte)0x00);
		verifyUserPIN();
		unsupportedINS(apdu);
	}

	@Test(groups = {"Failing"})
	public void unsupportedINSpin() throws Exception
	{
		byte[] apdu = AbstractClient.constructApdu(AbstractClient.CLA_CARD_KPNFC_PIN, (byte)0x00);
		unsupportedINS(apdu);
	}

	@Test(groups = {"Failing"}, dependsOnGroups = {"PIN"})
	public void uninitializedCardKeySettingPasswordKey() throws Exception
	{
		if (client.getCardType() != PHYSICAL) { // in PHYSICAL card no guarantee on uninitialization of Card Key can be given
			verifyUserPIN();
			byte[] apdu = AbstractClient.constructApdu((byte)0x71);
			assertGeneralCryptoError(apdu, "setPasswordKey should throw error if card hasn't any key.");
		}
	}

	public void assertIncorrectLength(byte[] apdu, String msg)
	{
		try {
			Assert.assertEquals(0x6700, client.sendAPDU(apdu).getSW());
			if (client.isThrowOnCommandException())
				Assert.fail(msg);
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("6700"));
		}
	}

	@Test(groups = {"Failing"}, dependsOnGroups = {"PIN"})
	public void incorrectLengthPasswordKey() throws Exception
	{
		verifyUserPIN();
		byte[] apdu = AbstractClient.constructApdu((byte)0x71, new byte[]{0x01, 0x02});
		assertIncorrectLength(apdu, "setPasswordKey should throw error if data is provided in request APDU.");
	}

	@Test(groups = {"Failing"}, dependsOnGroups = {"PIN"})
	public void uninitializedCardKeySettingTransactionKey() throws Exception
	{
		if (client.getCardType() != PHYSICAL) { // in PHYSICAL card no guarantee on uninitialization of Card Key can be given
			verifyUserPIN();
			byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_PREPARE_DECRYPTION, new byte[32]);
			assertGeneralCryptoError(apdu, "prepareDecryption should throw error if card hasn't any key.");
		}
	}

	@Test(groups = {"Failing"}, dependsOnGroups = {"PIN"})
	public void incorrectLengthTransactionKey() throws Exception
	{
		verifyUserPIN();
		byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_PREPARE_DECRYPTION);
		assertIncorrectLength(apdu, "prepareDecryption should throw error if no data is provided in request APDU.");
		apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_PREPARE_DECRYPTION, new byte[16]);
		assertIncorrectLength(apdu, "prepareDecryption should throw error if incorrect data length (16) is provided in request APDU.");
		apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_PREPARE_DECRYPTION, new byte[64]);
		assertIncorrectLength(apdu, "prepareDecryption should throw error if incorrect data length (64) is provided in request APDU.");
	}

	@Test(groups = {"Failing"}, dependsOnGroups = {"PIN"})
	public void incorrectLengthGenCardKey() throws Exception
	{
		verifyUserPIN();
		byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_GENERATE_CARD_KEY, new byte[]{0x01, 0x02});
		assertIncorrectLength(apdu, "generateCardKey should throw error if data is provided in request APDU.");
	}

	@Test(groups = {"Failing"}, dependsOnGroups = {"PIN"})
	public void incorrectLengthWriteToScratch() throws Exception
	{
		verifyUserPIN();
		// 0x104 = 260 is current length of scratch area. Testing with 0x102 length and 3 bytes goes after the end.
		byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_WRITE_TO_SCRATCH, new byte[]{0x01, 0x02, 0x03, 0x04, 0x05});
		assertIncorrectLength(apdu, "writeToScratch should throw error if data provided would go after the end of scratch area array.");
	}

	@Test(groups = {"Failing"}, dependsOnGroups = {"PIN"})
	public void incorrectLengthGetCardPubKey() throws Exception
	{
		verifyUserPIN();
		// expects 3 bytes, test with less and more
		byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_GET_CARD_PUBKEY, new byte[]{0x01, 0x02});
		assertIncorrectLength(apdu, "getCardPubKey should throw error if data provided is not 3 bytes.");
		apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_GET_CARD_PUBKEY, new byte[]{0x01, 0x02, 0x03, 0x04});
		assertIncorrectLength(apdu, "getCardPubKey should throw error if data provided is not 3 bytes.");
	}

	@Test(groups = {"PIN", "Failing"})
	public void incorrectMasterPIN() throws Exception
	{
		// tests incorrect Master PIN
		String errMsg = "VerifyMasterPIN should throw error if Master PIN doesn't match.";
		try {
			Assert.assertFalse(errMsg, client.verifyMasterPIN(null));
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("99"));
		}
		Assert.assertTrue(client.verifyMasterPIN(new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}));
		try {
			Assert.assertFalse(errMsg, client.verifyMasterPIN(new byte[]{0x36, 0x32, 0x33, 0x34, 0x35, 0x36}));
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("99"));
		}
		Assert.assertTrue(client.verifyMasterPIN(new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}));
		try {
			Assert.assertFalse(errMsg, client.verifyMasterPIN(new byte[]{0x36, 0x32, 0x33, 0x34, 0x35, 0x36, 0x36, 0x32, 0x33, 0x34, 0x35, 0x36}));
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("99"));
		}
		Assert.assertTrue(client.verifyMasterPIN(new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}));
	}

	@Test(groups = {"PIN", "Failing"})
	public void incorrectUserPIN() throws Exception
	{
		// tests incorrect User PIN
		String errMsg = "VerifyUserPIN should throw error if User PIN doesn't match.";
		try {
			Assert.assertFalse(errMsg, client.verifyUserPIN(null));
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("99"));
		}
		Assert.assertTrue(client.verifyUserPIN(new byte[]{0x31, 0x32, 0x33, 0x34}));
		try {
			Assert.assertFalse(errMsg, client.verifyUserPIN(new byte[]{0x36, 0x32, 0x33, 0x34, 0x35, 0x36}));
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("99"));
		}
		Assert.assertTrue(client.verifyUserPIN(new byte[]{0x31, 0x32, 0x33, 0x34}));
		try {
			Assert.assertFalse(errMsg, client.verifyUserPIN(new byte[]{0x36, 0x32, 0x33, 0x34, 0x35, 0x36, 0x36, 0x32, 0x33, 0x34, 0x35, 0x36}));
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("99"));
		}
		Assert.assertTrue(client.verifyUserPIN(new byte[]{0x31, 0x32, 0x33, 0x34}));
	}

	@Test(groups = {"PIN", "Failing"}, dependsOnMethods = {"verifyUserPIN", "verifyMasterPIN"})
	public void unverifiedSetUserPIN() throws Exception
	{
		// test failure of setting of User PIN
		String errMsg = "SetUserPIN should throw error if Master PIN isn't verified.";
		try {
			Assert.assertFalse(errMsg, client.setUserPIN(new byte[]{0x34, 0x37, 0x39, 0x36}));
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("97"));
		}
	}

	@Test(groups = {"PIN", "Failing"}, dependsOnMethods = {"verifyMasterPIN"})
	public void unverifiedSetMasterPIN() throws Exception
	{
		// test failure of setting of Master PIN
		String errMsg = "SetMasterPIN should throw error if old Master PIN isn't verified.";
		try {
			Assert.assertFalse(errMsg, client.setMasterPIN(new byte[]{0x34, 0x37, 0x39, 0x36}));
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("97"));
		}
	}

	@Test(groups = {"PIN", "Failing"}, dependsOnMethods = {"verifyMasterPIN"})
	public void setShortMasterPIN() throws Exception
	{
		// test setting of a too short Master PIN
		String errMsg = "SetMasterPIN should throw error if new Master PIN isn't long enough.";
		byte[] newPIN = new byte[]{0x34, 0x37, 0x39, 0x36};
		try {
			Assert.assertFalse(errMsg, client.setMasterPIN(newPIN, new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}));
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("6700"));
		}
	}

	@Test(groups = {"PIN"})
	public void verifyMasterPIN() throws Exception
	{
		// test verifying User PIN
		Assert.assertTrue("Default Master PIN should be correctly verified.",
				client.verifyMasterPIN(new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}));
	}

	@Test(groups = {"PIN"})
	public void verifyUserPIN() throws Exception
	{
		// test verifying User PIN
		Assert.assertTrue("Default User PIN should be correctly verified.",
				client.verifyUserPIN(new byte[]{0x31, 0x32, 0x33, 0x34}));
	}

	@Test(groups = {"PIN"}, dependsOnMethods = {"verifyMasterPIN", "verifyUserPIN"})
	public void setUserPIN() throws Exception
	{
		// test setting of User PIN
		byte[] newPIN = new byte[]{0x34, 0x37, 0x39, 0x36};
		Assert.assertTrue("SetUserPIN should work after Master PIN verification.",
				client.setUserPIN(newPIN, new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}));
		Assert.assertTrue("If new User PIN is set, it should be correctly verified.",
				client.verifyUserPIN(newPIN));
		Assert.assertTrue("SetUserPIN should work after Master PIN verification.",
				client.setUserPIN(new byte[]{0x31, 0x32, 0x33, 0x34}, new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}));
	}

	@Test(groups = {"PIN", "Failing"}, dependsOnMethods = {"verifyMasterPIN"})
	public void setShortUserPIN() throws Exception
	{
		// test setting of a too short Master PIN
		String errMsg = "SetMasterPIN should throw error if new Master PIN isn't long enough.";
		byte[] newPIN = new byte[]{0x34, 0x37, 0x39};
		try {
			Assert.assertFalse(errMsg, client.setUserPIN(newPIN, new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}));
		} catch (CardException e) {
			Assert.assertTrue(e.getMessage().startsWith("6700"));
		}
	}

	@Test(groups = {"PIN"}, dependsOnMethods = {"verifyMasterPIN"})
	public void setMasterPIN() throws Exception
	{
		// test setting of User PIN
		byte[] newPIN = new byte[]{0x31, 0x33, 0x33, 0x37, 0x31, 0x33, 0x33, 0x37};
		Assert.assertTrue("SetMasterPIN should work after Master PIN verification.",
				client.setMasterPIN(newPIN, new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}));
		Assert.assertTrue("If new Master PIN is set, it should be correctly verified.",
				client.verifyMasterPIN(newPIN));
		Assert.assertTrue("SetMasterPIN should work after Master PIN verification.",
				client.setMasterPIN(new byte[]{0x31, 0x32, 0x33, 0x34, 0x35, 0x36}, newPIN));
	}
}
