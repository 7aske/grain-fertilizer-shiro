package com._7aske.grain.fertilizer.shiro.realm;

import com._7aske.grain.fertilizer.shiro.authentication.ShiroAuthentication;
import com._7aske.grain.fertilizer.shiro.authentication.ShiroSubject;
import com._7aske.grain.security.Authority;
import com._7aske.grain.security.User;
import com._7aske.grain.security.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class UserServiceRealm extends AuthorizingRealm {
    private final UserService userService;
    private final String name;

    public UserServiceRealm(UserService userService, String name) {
        this.userService = userService;
        this.name = name;
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return ShiroSubject.class.isAssignableFrom(token.getClass());
    }
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        //null usernames are invalid
        if (principals == null) {
            throw new AuthorizationException("PrincipalCollection method argument cannot be null.");
        }

        String username = (String) getAvailablePrincipal(principals);

        Set<String> roleNames = null;
        // TODO: implement permissions
        Set<String> permissions = null;

        User user = userService.findByUsername(username);
        if (user == null) {
            throw new AuthorizationException("User not found");
        }

        roleNames = ((Collection<? extends Authority>) user.getAuthorities())
                .stream()
                .map(Authority::getName)
                .collect(Collectors.toSet());

        // TODO set permissions
        return new SimpleAuthorizationInfo(roleNames);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        if (token instanceof ShiroSubject subject) {
            String username = subject.getName();

            // Null username is invalid
            if (username == null) {
                throw new AccountException("Null usernames are not allowed by this realm.");
            }

            User user = userService.findByUsername(username);

            ShiroSubject shiroSubject = ShiroSubject.builder()
                    .name(user.getUsername())
                    .principal(user)
                    .credentials(user.getPassword())
                    .authorities(user.getAuthorities())
                    .securityManager(SecurityUtils.getSecurityManager())
                    .build();

            return new SimpleAuthenticationInfo(shiroSubject, shiroSubject.getCredentials(), getName());
        }

        throw new AuthenticationException("Token must be of type ShiroAuthentication");
    }
}
