package com._7aske.grain.fertilizer.shiro.authentication;

import com._7aske.grain.security.Authentication;
import com._7aske.grain.security.Authority;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;

import java.util.Collection;

public class ShiroAuthentication implements Authentication {
    private Subject subject;

    public ShiroAuthentication(Subject subject) {
        this.subject = subject;
    }

    @Override
    public String getName() {
        Object value = subject.getPrincipal();
        if (value instanceof String str) {
            return str;
        } else if (value instanceof ShiroSubject subj) {
            return subj.getName();
        }

        throw new IllegalStateException("Principal type not supported: " + value.getClass());
    }

    @Override
    public Object getCredentials() {
        Object principal = subject.getPrincipal();
        if (principal instanceof AuthenticationToken token) {
            return token.getCredentials();
        }

        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return subject.isAuthenticated();
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        throw new UnsupportedOperationException("Not implemented");

    }

    @Override
    public Collection<? super Authority> getAuthorities() {
        Object principal = subject.getPrincipal();
        if (principal instanceof ShiroSubject shiroSubject) {
            return shiroSubject.getAuthorities();
        }

        throw new IllegalStateException("Principal type not supported: " + principal.getClass());
    }

    @Override
    public void setAuthorities(Collection<? super Authority> authorities) {
        throw new UnsupportedOperationException("Not implemented");
    }
}
