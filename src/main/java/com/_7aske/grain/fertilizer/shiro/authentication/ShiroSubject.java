package com._7aske.grain.fertilizer.shiro.authentication;

import com._7aske.grain.security.Authentication;
import com._7aske.grain.security.Authority;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.support.DelegatingSubject;

import java.util.ArrayList;
import java.util.Collection;

public class ShiroSubject extends DelegatingSubject implements Authentication, AuthenticationToken {
    private final String name;
    private final Object credentials;
    private Collection<? super Authority> authorities = new ArrayList<>();

    public ShiroSubject(String name, Object principal, Object credentials, Collection<? super Authority> authorities, SecurityManager securityManager) {
        super(securityManager);
        if (principal != null) {
            this.principals = new SimplePrincipalCollection(principal, "default");
        }
        this.name = name;
        this.credentials = credentials;
        this.authorities = authorities;
    }

    @Override
    public Object getPrincipal() {
        return principals.getPrimaryPrincipal();
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        super.authenticated = authenticated;
    }

    @Override
    public Collection<? super Authority> getAuthorities() {
        return authorities;
    }

    @Override
    public void setAuthorities(Collection<? super Authority> authorities) {
        this.authorities = authorities;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String name;
        private Object principal;
        private Object credentials;
        private Collection<? super Authority> authorities;
        private SecurityManager securityManager;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder principal(Object principal) {
            this.principal = principal;
            return this;
        }

        public Builder credentials(Object credentials) {
            this.credentials = credentials;
            return this;
        }

        public Builder authorities(Collection<? super Authority> authorities) {
            this.authorities = authorities;
            return this;
        }

        public Builder securityManager(SecurityManager securityManager) {
            this.securityManager = securityManager;
            return this;
        }

        public ShiroSubject build() {
            return new ShiroSubject(name, principal, credentials, authorities, securityManager);
        }
    }
}
