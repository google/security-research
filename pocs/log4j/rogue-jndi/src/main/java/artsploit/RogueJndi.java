package artsploit;

public class RogueJndi {

    public static void main(String[] args) throws Exception {
        System.out.println(
            "+-+-+-+-+-+-+-+-+-+\n" +
            "|R|o|g|u|e|J|n|d|i|\n" +
            "+-+-+-+-+-+-+-+-+-+"
        );
        Config.applyCmdArgs(args);
        HttpServer.start();
        LdapServer.start();
    }
}