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
	private static CardToolsClient client = null;

	public AppletTest()
	{
	}

	@BeforeClass
	public static void setUpClass() throws Exception
	{
		client = new CardToolsClient(KeepassNFC.class, "F0375472804FD5FA0F243E42C1B63825");
		client.setThrowOnCommandException(false);
		client.setCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
	}

	@AfterClass
	public static void tearDownClass() throws Exception
	{
		// client.Disconnect(true);
	}

	@BeforeMethod
	public void setUpMethod() throws Exception
	{
	}

	@AfterMethod
	public void tearDownMethod() throws Exception
	{
	}

	// Install Test
	@Test(groups = {"Installing"})
	public void installTest() throws Exception
	{
		final CardManager cardMngr = client.installSelectApplet();
		Assert.assertEquals(cardMngr.getAppletId(), client.getAppletAIDByte());
	}

	// Simulator/dummy test
	@Test(groups = {"Installing"}, priority = 1)
	public void dummyCommand() throws Exception
	{
		final ResponseAPDU responseAPDU = client.dummyCommand();
		Assert.assertNotNull(responseAPDU);
		Assert.assertEquals(0x9000, responseAPDU.getSW());
		Assert.assertNotNull(responseAPDU.getBytes());
	}

	//@Test(dependsOnGroups = {"Installing"})
}
