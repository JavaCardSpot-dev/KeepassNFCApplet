package tests;

import cardTools.CardManager;
import cardTools.RunConfig;
import net.lardcave.keepassnfcapplet.KeepassNFC;
import org.junit.Assert;
import org.testng.annotations.*;

import javax.crypto.IllegalBlockSizeException;
import javax.smartcardio.CardException;
import java.security.interfaces.RSAPublicKey;

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
		client.setThrowOnCommandException(false);
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
		Assert.assertEquals((byte)1, version[1]);
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

	@Test(dependsOnGroups = {"Configuring"})
	public void cardDecrypt() throws Exception
	{
		client.generateCardKey();
		client.setNewPasswordKey();
		client.setPasswordKeyIv();
		byte[] data = "TestDataCorrectL".getBytes();
		byte[] encryptedData = client.encrypt(data);
		byte[] decryptedData = client.decrypt(encryptedData);
		Assert.assertEquals(data, decryptedData);
	}

	@Test(groups = {"Failing"})
	public void unsupportedCLA() throws Exception
	{
		try {
			byte[] apdu = client.constructApdu((byte)0x00);
			apdu[0] = 0x00;
			client.sendAPDU(client.getCardMngr(), apdu);
			Assert.fail("Unsupported CLA should throw errors.");
		} catch (CardException ignored) {
		}
	}

	@Test(groups = {"Failing"})
	public void unsupportedINS() throws Exception
	{
		try {
			client.sendAPDU(client.getCardMngr(), client.constructApdu((byte)0x00));
			Assert.fail("Unsupported INS should throw errors.");
		} catch (CardException ignored) {
		}
	}
}
