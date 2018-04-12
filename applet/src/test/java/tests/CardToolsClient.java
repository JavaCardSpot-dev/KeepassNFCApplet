package tests;

import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import javax.smartcardio.*;
import java.util.ArrayList;

/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda, Dusan Klinec (ph4r05), Marco Ciotola (McCio)
 */
public class CardToolsClient extends AbstractClient {
	private Class appletClass = null;

	private String APPLET_AID = "F0375472804FD5FA0F243E42C1B63825";
	private byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);

	private RunConfig.CARD_TYPE cardType = RunConfig.CARD_TYPE.JCARDSIMLOCAL; // RunConfig.CARD_TYPE.PHYSICAL for real card

	private boolean throwOnCommandException = true;
	private final static String STR_APDU_DUMMY = "00C00000080000000000000000";

	private CardManager cardMngr = null;

	protected CardToolsClient(Class appletClass, String APPLET_AID)
	{
		setAppletClass(appletClass);
		setAppletAID(APPLET_AID);
	}

	protected CardToolsClient(Class appletClass, byte[] APPLET_AID)
	{
		setAppletClass(appletClass);
		setAppletAID(APPLET_AID);
	}

	public void setAppletClass(Class cls)
	{
		appletClass = cls;
	}

	public void setAppletAID(String aid)
	{
		APPLET_AID = aid;
		APPLET_AID_BYTE = Util.hexStringToByteArray(APPLET_AID);
	}

	public void setAppletAID(byte[] aid)
	{
		APPLET_AID = Util.bytesToHex(aid);
		APPLET_AID_BYTE = aid;
	}

	public String getAppletAID()
	{
		return APPLET_AID;
	}

	public byte[] getAppletAIDByte()
	{
		return APPLET_AID_BYTE;
	}

	public void setCardType(RunConfig.CARD_TYPE card_type)
	{
		cardType = card_type;
	}

	public void setThrowOnCommandException(boolean throwOnException)
	{
		throwOnCommandException = throwOnException;
	}

	@Override
	protected short getShort(byte[] buffer, int idx)
	{
		return Util.getShort(buffer, idx);
	}

	@Override
	protected void putShort(byte[] args, int idx, short val)
	{
		byte[] tmp = Util.shortToByteArray(val);
		args[idx] = tmp[0];
		args[idx + 1] = tmp[1];
	}

	@Override
	public String toHex(byte[] data)
	{
		return Util.toHex(data);
	}

	@Override
	public byte[] decodeHexString(String s)
	{
		return Util.hexStringToByteArray(s);
	}

	public ResponseAPDU sendAPDU(CardChannel channel, final CommandAPDU request) throws CardException
	{
		ResponseAPDU resp = channel.transmit(request);
		System.out.printf("Response SW is %02X", resp.getSW());
		if (resp.getSW() != 0x9000) {
			System.out.println(" - ERROR");
			System.out.flush();
			String msg;
			switch (resp.getSW()) {
				case 0xF102:
					msg = "CryptoException: Uninitialized key";
					break;
				case 0x6D00:
					msg = "CardException: INS not supported";
					break;
				default:
					msg = "Some error occurred executing a command";
					break;
			}
			if (throwOnCommandException) {
				throw new CardException(msg);
			} else {
				System.err.println(msg);
				System.err.flush();
			}
		} else {
			System.out.println(" - OK");
		}
		return resp;
	}

	public ResponseAPDU sendAPDU(CardManager cardMngr, final String request) throws CardException
	{
		return sendAPDU(cardMngr.getChannel(), Util.hexStringToByteArray(request));
	}

	public ResponseAPDU sendAPDU(CardManager cardMngr, byte[] apdu) throws CardException
	{
		return sendAPDU(cardMngr.getChannel(), new CommandAPDU(apdu));
	}

	public CardManager installSelectApplet(byte[] installData) throws CardException
	{
		cardMngr = new CardManager(true, APPLET_AID_BYTE);
		final RunConfig runCfg = RunConfig.getDefaultConfig();

		runCfg.setAppletToSimulate(appletClass)
				.setTestCardType(cardType)
				.setbReuploadApplet(true);

		if (installData != null)
			runCfg.setInstallData(installData);

		System.out.print("Connecting to card...");
		try {
			if (!cardMngr.Connect(runCfg)) {
				throw new CardException("Couldn't connect to card");
			}
		} catch (Exception e) {
			throw new CardException("Couldn't connect to card", e);
		}
		System.out.println(" Done.");

		return cardMngr;
	}

	public CardManager installSelectApplet() throws CardException
	{
		return installSelectApplet(null);
	}

	public CardManager getCardMngr()
	{
		return cardMngr;
	}

	/**
	 * Sending command to the card.
	 * Enables to send init commands before the main one.
	 *
	 * @param cardMngr     CardManager to use
	 * @param command      main command to execute
	 * @param initCommands commands needed by main one to succeed
	 * @return ResponseAPDU of last command
	 * @throws CardException propagated during command execution
	 */
	public ResponseAPDU sendCommandWithInitSequence(CardManager cardMngr, String command, ArrayList<String> initCommands)
			throws CardException
	{
		if (initCommands != null) {
			for (String cmd : initCommands) {
				sendAPDU(cardMngr, cmd);
			}
		}

		return sendAPDU(cardMngr, command);
	}

	public ResponseAPDU dummyCommand(CardManager cardMngr) throws Exception
	{
		return sendCommandWithInitSequence(cardMngr, STR_APDU_DUMMY, null);
	}

	public ResponseAPDU dummyCommand() throws Exception
	{
		return dummyCommand(getCardMngr());
	}

	@Override
	public CardChannel getCardChannel() throws CardException
	{
		return cardMngr.getChannel();
	}

	@Override
	public CardChannel getNewCardChannel() throws CardException
	{
		return installSelectApplet().getChannel();
	}

	@Override
	public CardTerminal getFirstCardTerminal() throws CardException
	{
		throw new NotImplementedException();
	}

}
