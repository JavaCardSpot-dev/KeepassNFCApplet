package tests;

import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
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
	private RunConfig.CARD_TYPE cardType = RunConfig.CARD_TYPE.JCARDSIMLOCAL;
	private CardToolsClient client = null;

	public AppletTest()
	{
	}

	// install test first
	@BeforeGroups(groups = {"Installing"})
	public void setUpInstalling() throws Exception
	{
		client = new CardToolsClient(KeepassNFC.class, "F0375472804FD5FA0F243E42C1B63825");
		client.setThrowOnCommandException(true);
		client.setCardType(cardType);
	}

	@AfterGroups(groups = {"Installing"})
	public void tearDownClient() throws Exception
	{
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
		byte[] version = client.getVersion();
		Assert.assertEquals((byte)1, version[0]);
		Assert.assertEquals((byte)2, version[1]);
	}

	@Test(dependsOnGroups = {"Installing"}, groups = {"Configuring"})
	public void setupNewCardKey() throws Exception
	{
		short keyLength = client.generateCardKey();
		Assert.assertEquals((2048 + 64)/8, keyLength);
		RSAPublicKey key = client.getCardPubKey(client.getCardChannel());
		Assert.assertEquals("RSA", key.getAlgorithm());
		Assert.assertEquals("X.509", key.getFormat());
		Assert.assertEquals(2048, key.getModulus().bitLength());
		Assert.assertTrue(key.getPublicExponent().isProbablePrime(10));
	}

	@Test(dependsOnGroups = {"Configuring"})
	public void setPasswordKey() throws Exception
	{
		client.generateCardKey();
		boolean passwordSet = client.setNewPasswordKey("ASD");
		Assert.assertEquals(true, passwordSet);
	}

	@Test(dependsOnGroups = {"Configuring"})
	public void setDefaultPasswordKey() throws Exception
	{
		client.useDefaultKey = true;
		client.generateCardKey();
		boolean passwordSet = client.setNewPasswordKey();
		Assert.assertEquals(true, passwordSet);
	}

	@Test(dependsOnGroups = {"Configuring"})
	public void setRandomPasswordKey() throws Exception
	{
		client.generateCardKey();
		boolean passwordSet = client.setNewPasswordKey();
		Assert.assertEquals(true, passwordSet);
	}

	@Test(dependsOnGroups = {"Configuring"})
	public void clientEncrypt() throws Exception
	{
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
	@Test(dependsOnGroups = {"Configuring"})
	public void cardDecrypt16() throws Exception
	{
		cardDecrypt("TestDataCorrectL".getBytes());
	}

	@Test(dependsOnGroups = {"Configuring"})
	public void cardDecrypt32() throws Exception
	{
		cardDecrypt("TestDataCorrectLengthThats32Byte".getBytes());
	}

	@Test(dependsOnGroups = {"Configuring"})
	public void cardDecrypt64() throws Exception
	{
		cardDecrypt("TestDataCorrectLengthThats32ByteTestDataCorrectLengthThats32Byte".getBytes());
	}

	@Test(groups = {"Failing"})
	public void unsupportedCLA() throws Exception
	{
		try {
			byte[] apdu = client.constructApdu((byte)0x00);
			apdu[0] = 0x00;
			client.sendAPDU(apdu);
			Assert.fail("Unsupported CLA should throw errors.");
		} catch (CardException ignored) {
		}
	}

	@Test(groups = {"Failing"})
	public void unsupportedINS() throws Exception
	{
		try {
			client.sendAPDU(client.constructApdu((byte)0x00));
			Assert.fail("Unsupported INS should throw errors.");
		} catch (CardException ignored) {
		}
	}

	@Test(groups = {"Failing"})
	public void uninitializedCardKeySettingPasswordKey() throws Exception
	{
		try {
			client.sendAPDU(client.constructApdu((byte)0x71));
			Assert.fail("setPasswordKey should throw error if card hasn't any key.");
		} catch (CardException ignored) {
		}
	}

	@Test(groups = {"Failing"})
	public void uncorrectLengthPasswordKey() throws Exception
	{
		try {
			byte[] apdu = client.constructApdu((byte)0x71, new byte[]{0x01, 0x02});
			client.sendAPDU(apdu);
			Assert.fail("setPasswordKey should throw error if data is provided in request APDU.");
		} catch (CardException ignored) {
		}
	}

	@Test(groups = {"Failing"})
	public void uninitializedCardKeySettingTransactionKey() throws Exception
	{
		try {
			client.sendAPDU(AbstractClient.constructApdu(AbstractClient.INS_CARD_PREPARE_DECRYPTION, new byte[32]));
			Assert.fail("prepareDecryption should throw error if card hasn't any key.");
		} catch (CardException ignored) {
		}
	}

	@Test(groups = {"Failing"})
	public void incorrectLengthTransactionKey() throws Exception
	{
		try {
			byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_PREPARE_DECRYPTION);
			client.sendAPDU(apdu);
			Assert.fail("prepareDecryption should throw error if no data is provided in request APDU.");
		} catch (CardException ignored) {
		}
		try {
			byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_PREPARE_DECRYPTION, new byte[16]);
			client.sendAPDU(apdu);
			Assert.fail("prepareDecryption should throw error if incorrect data length (16) is provided in request APDU.");
		} catch (CardException ignored) {
		}
		try {
			byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_PREPARE_DECRYPTION, new byte[64]);
			client.sendAPDU(apdu);
			Assert.fail("prepareDecryption should throw error if incorrect data length (64) is provided in request APDU.");
		} catch (CardException ignored) {
		}
	}

	@Test(groups = {"Failing"})
	public void incorrectLengthGenCardKey() throws Exception
	{
		try {
			byte[] apdu = client.constructApdu(AbstractClient.INS_CARD_GENERATE_CARD_KEY, new byte[]{0x01, 0x02});
			client.sendAPDU(apdu);
			Assert.fail("generateCardKey should throw error if data is provided in request APDU.");
		} catch (CardException ignored) {
		}
	}

	@Test(groups = {"Failing"})
	public void incorrectLengthWriteToScratch() throws Exception
	{
		try {
			// 0x104 = 260 is current length of scratch area. Testing with 0x102 length and 3 bytes goes after the end.
			byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_WRITE_TO_SCRATCH, new byte[]{0x01, 0x02, 0x03, 0x04, 0x05});
			client.sendAPDU(apdu);
			Assert.fail("writeToScratch should throw error if data provided would go after the end of scratch area array.");
		} catch (CardException ignored) {
		}
	}

	@Test(groups = {"Failing"})
	public void incorrectLengthGetCardPubKey() throws Exception
	{
		// expects 3 bytes, test with less and more
		try {
			byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_GET_CARD_PUBKEY, new byte[]{0x01, 0x02});
			client.sendAPDU(apdu);
			Assert.fail("getCardPubKey should throw error if data provided is not 3 bytes.");
		} catch (CardException ignored) {
		}
		try {
			byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_CARD_GET_CARD_PUBKEY, new byte[]{0x01, 0x02, 0x03, 0x04});
			client.sendAPDU(apdu);
			Assert.fail("getCardPubKey should throw error if data provided is not 3 bytes.");
		} catch (CardException ignored) {
		}
	}
        @Test(groups = {"Failing"})
	public void incorrectMaster_PIN() throws Exception
	{
		// tests incorrect MasterPIN
		try {
			byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_VERIFY_MasterPIN, new byte[]{0x36, 0x32,0x33,0x34,0x35,0x36});
			client.sendAPDU(apdu);
			Assert.fail("VerifyMasterPIN should throw error if Master PIN doesn't match.");
		} catch (CardException ignored) {
		}
		
	}
         @Test(groups = {"Failing"})
	public void incorrectUser_PIN() throws Exception
	{
		// tests incorrect MasterPIN
		try {
			byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_VERIFY_UserPIN, new byte[]{0x36, 0x32,0x33,0x34});
			client.sendAPDU(apdu);
			Assert.fail("VerifyUserPIN should throw error if Master PIN doesn't match.");
		} catch (CardException ignored) {
		}
		
	}
        public void SetUser_PIN() throws Exception
	{
		// test failure of setting of user PIN
		try {
			byte[] apdu = AbstractClient.constructApdu(AbstractClient.INS_SET_UserPIN, new byte[]{0x34, 0x37,0x39,0x36});
			client.sendAPDU(apdu);
			Assert.fail("SetUserPIN should throw error if user PIN doesn't set.");
		} catch (CardException ignored) {
		}
		
	}
}
