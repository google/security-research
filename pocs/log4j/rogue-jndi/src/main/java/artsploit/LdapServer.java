package artsploit;

import artsploit.annotations.LdapMapping;
import artsploit.controllers.LdapController;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import org.reflections.Reflections;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.lang.reflect.Constructor;
import java.net.InetAddress;
import java.util.Set;
import java.util.TreeMap;

class LdapServer extends InMemoryOperationInterceptor {

    TreeMap<String, LdapController> routes = new TreeMap<>();

    public static void start() {
        try {
            System.out.println("Starting LDAP server on 0.0.0.0:" + Config.ldapPort);
            InMemoryDirectoryServerConfig serverConfig = new InMemoryDirectoryServerConfig("dc=example,dc=com");
            serverConfig.setListenerConfigs(new InMemoryListenerConfig(
                    "listen",
                    InetAddress.getByName("0.0.0.0"),
                    Config.ldapPort,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            serverConfig.addInMemoryOperationInterceptor(new LdapServer());
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(serverConfig);
            ds.startListening();
        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    public LdapServer() throws Exception {

        //find all classes annotated with @LdapMapping
        Set<Class<?>> controllers = new Reflections(this.getClass().getPackage().getName())
                .getTypesAnnotatedWith(LdapMapping.class);

        //instantiate them and store in the routes map
        for(Class<?> controller : controllers) {
            Constructor<?> cons = controller.getConstructor();
            LdapController instance = (LdapController) cons.newInstance();
            String[] mappings = controller.getAnnotation(LdapMapping.class).uri();
            for(String mapping : mappings) {
                if(mapping.startsWith("/"))
                    mapping = mapping.substring(1); //remove first forward slash

                System.out.printf("Mapping ldap://%s:%s/%s to %s\n",
                        Config.hostname, Config.ldapPort, mapping, controller.getName());
                routes.put(mapping, instance);
            }
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)
     */
    @Override
    public void processSearchResult(InMemoryInterceptedSearchResult result) {
        String base = result.getRequest().getBaseDN();
        LdapController controller = null;
        //find controller
        for(String key: routes.keySet()) {
            //compare using wildcard at the end
            if(key.equals(base) || key.endsWith("*") && base.startsWith(key.substring(0, key.length()-1))) {
                controller = routes.get(key);
                break;
            }
        }
        try {
            controller.sendResult(result, base);
        } catch (Exception e1) {
            e1.printStackTrace();
        }
    }
}
