package net.lardcave.keepassnfc.javaclient;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

import javax.smartcardio.*;
import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("WeakerAccess")
public class JCommanderClient extends AbstractClient {
    @Parameter(names="-chat", description="Show APDU (smartcard) communication")
    public boolean showChat;

    @Parameter(names="-password-key", description="Password key (hex)")
    public String passwordKeyString;

    @Parameter(names="-default-key", description="Use test values for password key")
    public boolean useDefaultKey;

    @Parameter(names="-data", description="Data (hex string)")
    public String testDataString;
    
    @Parameter(names="-reader", description="reader id 0-9")
    public static int nReaderIndex = 0;

    @Parameter(description="Command {set_card_key, set_password_key, encrypt, decrypt}")
    public List<String> command = new ArrayList<>();

    public static final byte[] selectAppletAPDU = {
            (byte)0x00, // cla
            (byte)0xA4, // ins
            (byte)0x04, // P1
            (byte)0x00, // P2
            (byte)0x10, // Length of AID,
            (byte)0xf0, (byte)0x37, (byte)0x54, (byte)0x72, (byte)0x80, (byte)0x4f, (byte)0xd5, (byte)0xfa, // AID
            (byte)0x0f, (byte)0x24, (byte)0x3e, (byte)0x42, (byte)0xc1, (byte)0xb6, (byte)0x38, (byte)0x25, // AID
            (byte)0x00, // apparently optional
    };

    public static void main(String[] args) throws CardException {

        JCommanderClient client = new JCommanderClient();
	    client.TEST_PASSWORD_KEY = new byte[]{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
	    client.TEST_INPUT = new byte[]{(byte)0x70, (byte)0x65, (byte)0x72, (byte)0x73, (byte)0x69,
			    (byte)0x6d, (byte)0x6d, (byte)0x6f, (byte)0x6e, (byte)0x73, (byte)0x20, (byte)0x2d, (byte)0x20,
			    (byte)0x79, (byte)0x75, (byte)0x6d};
	    // client.passwordKey = new byte[]{};
	    // client.passwordKey = null;
	    // client.passwordKeyIv;
	    // client.testData;
        new JCommander(client, args);

        client.run();
    }

    public CardChannel getCardChannel() throws CardException {

        CardTerminal terminal = getFirstCardTerminal();

        if(terminal == null)
            return null;

        if(!terminal.isCardPresent()) {
            System.err.println("No card present in first terminal");
            return null;
        }


        Card card = terminal.connect("*");
        CardChannel channel = card.getBasicChannel();

        // Terminal-specific: ACR122U pseudo-APDU to set card timeout.
        // timeout parameter is in units of 5 seconds, or 00 for no timeout, or ff for "wait until contactless chip responds"
        ResponseAPDU response;
        byte timeout = (byte)(1200 / 5);
        byte[] acr_timeout_apdu = {(byte)0xff, (byte)0x00, (byte)0x41, timeout, (byte)0};
        //sendAPDU(channel, acr_timeout_apdu);

        // reset card (?!)
        ATR atr = card.getATR();

        // Select applet
        response = sendAPDU(channel, selectAppletAPDU);
        byte[] responseBytes = response.getBytes();

        if(responseBytes[0] != (byte)0x90 && responseBytes[1] != (byte)0x00) {
            System.out.println("Applet select failed: " + toHex(responseBytes));
            // see https://www.eftlab.com.au/index.php/site-map/knowledge-base/118-apdu-response-list

            return null;
        }

        return channel;
    }

    @Override
    public CardChannel getNewCardChannel() throws CardException
    {
        return getCardChannel();
    }

    public CardTerminal getFirstCardTerminal() throws CardException {
        TerminalFactory terminalFactory = TerminalFactory.getDefault();

        List<CardTerminal> readers = terminalFactory.terminals().list();
        if(readers.size() == 0) {
            System.err.println("No card terminals found.");
            return null;
        } else {
            return readers.get(nReaderIndex);
        }
    }

    @Override
    public ResponseAPDU sendAPDU(CardChannel channel, CommandAPDU apdu) throws CardException
    {
        if(showChat)
            System.out.println("OUT: " + toHex(apdu.getBytes()));

        ResponseAPDU response = channel.transmit(apdu);

        if(showChat)
            System.out.println("IN:  " + toHex(response.getBytes()));
        return response;
    }

}
