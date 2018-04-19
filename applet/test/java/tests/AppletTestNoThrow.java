package tests;

public class AppletTestNoThrow extends AppletTest {
	@Override
	public void setUpInstalling() throws Exception
	{
		super.setUpInstalling();
		client.setThrowOnCommandException(false);
	}
}
