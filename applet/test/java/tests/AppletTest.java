package tests;

import cardTools.CardManager;
import cardTools.RunConfig;
import net.lardcave.keepassnfcapplet.KeepassNFC;
import org.junit.Assert;
import org.testng.annotations.*;

import javax.smartcardio.ResponseAPDU;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
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
	public void tearDownInstalling() throws Exception
	{
		client.getCardMngr().Disconnect(true);
	}

	// Real Install Test
	@Test(groups = {"Installing"})
	public void installTest() throws Exception
	{
		final CardManager cardMngr = client.installSelectApplet();
		Assert.assertEquals(cardMngr.getAppletId(), client.getAppletAIDByte());
	}

	// initialization before every method after install test
	@BeforeMethod(dependsOnGroups = {"Installing"})
	public void setUpMethod() throws Exception
	{
		client = new CardToolsClient(KeepassNFC.class, "F0375472804FD5FA0F243E42C1B63825");
		client.setThrowOnCommandException(false);
		client.setCardType(cardType);
		client.installSelectApplet();
	}

	@AfterMethod(dependsOnGroups = {"Installing"})
	public void tearDownMethod() throws Exception
	{
		client.getCardMngr().Disconnect(true);
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

	//@Test(dependsOnGroups = {"Installing"})
}