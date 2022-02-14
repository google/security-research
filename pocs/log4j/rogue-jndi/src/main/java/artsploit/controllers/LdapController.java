package artsploit.controllers;

import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;

public interface LdapController {
    void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception;
}
