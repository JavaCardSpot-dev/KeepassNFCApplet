package tests;

import cardTools.CardManager;
import cardTools.RunConfig;
import net.lardcave.keepassnfcapplet.KeepassNFC;
import org.junit.Assert;
import org.testng.annotations.*;

import javax.smartcardio.ResponseAPDU;
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

	// Simulator/dummy test
	@Test(dependsOnGroups = {"Installing"}, priority = 1)
	public void dummyCommand() throws Exception
	{
		final ResponseAPDU responseAPDU = client.dummyCommand();
		Assert.assertNotNull(responseAPDU);
		Assert.assertEquals(0x9000, responseAPDU.getSW());
		Assert.assertNotNull(responseAPDU.getBytes());
	}

	@Test(dependsOnGroups = {"Installing"})
	public void setupNewKey() throws Exception
	{
		client.generateCardKey();
		RSAPublicKey key = client.getCardPubKey(client.getCardChannel());
		Assert.assertEquals("RSA", key.getAlgorithm());
		Assert.assertEquals("X.509", key.getFormat());
		Assert.assertEquals(2048, key.getModulus().bitLength());
		Assert.assertTrue(key.getPublicExponent().isProbablePrime(10));
	}
}
