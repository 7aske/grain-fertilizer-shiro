package com._7aske.grain.fertilizer.shiro;

import com._7aske.grain.core.component.Grain;
import com._7aske.grain.fertilizer.shiro.authentication.ShiroAuthentication;
import com._7aske.grain.fertilizer.shiro.authentication.ShiroSubject;
import com._7aske.grain.security.Authentication;
import com._7aske.grain.security.CookieAuthentication;
import com._7aske.grain.security.SecurityConstants;
import com._7aske.grain.security.authentication.AuthenticationEntryPoint;
import com._7aske.grain.security.exception.*;
import com._7aske.grain.web.http.GrainHttpResponse;
import com._7aske.grain.web.http.HttpRequest;
import com._7aske.grain.web.http.HttpResponse;
import com._7aske.grain.web.http.session.Cookie;
import com._7aske.grain.web.http.session.SessionConstants;
import com._7aske.grain.web.http.session.SessionStore;
import org.apache.shiro.authc.*;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;

import java.util.UUID;

import static com._7aske.grain.web.http.session.SessionConstants.SESSION_COOKIE_NAME;

@Grain
public class ShiroFormLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final SecurityManager securityManager;
    private final SessionStore sessionStore;

    public ShiroFormLoginAuthenticationEntryPoint(SecurityManager securityManager, SessionStore sessionStore) {
        this.securityManager = securityManager;
        this.sessionStore = sessionStore;
    }

    @Override
    public Authentication authenticate(HttpRequest request, HttpResponse response) throws GrainSecurityException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        if (username == null || password == null) {
            return null;
        }

        try {
            AuthenticationInfo authenticate = securityManager.authenticate(ShiroSubject.builder()
                    .name(username)
                    .credentials(password)
                    .securityManager(securityManager)
                    .build());
            ShiroSubject subject = (ShiroSubject) authenticate.getPrincipals().getPrimaryPrincipal();

            Cookie gsid = null;
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(SESSION_COOKIE_NAME)) {
                    gsid = cookie;
                }
            }
            if (gsid == null) {
                gsid = new Cookie(SESSION_COOKIE_NAME, UUID.randomUUID().toString());
                gsid.setMaxAge((int) (System.currentTimeMillis() / 1000 + SessionConstants.SESSION_DEFAULT_MAX_AGE));
            }

            Authentication authentication = new CookieAuthentication(username, gsid, subject.getAuthorities());
            sessionStore.setToken(gsid.getId(), gsid);
            sessionStore.put(gsid.getId(), SecurityConstants.AUTHENTICATION_KEY, authentication);

            // @Incomplete invalidate the session of the incoming request if it had one
            // @Hack
            if (response instanceof GrainHttpResponse res) {
                res.setCookie(gsid);
            } else {
                response.addCookie(gsid);
            }

            return new ShiroAuthentication((Subject) authenticate.getPrincipals().getPrimaryPrincipal());
        } catch (ExpiredCredentialsException e) {
            throw new CredentialsExpiredException("Credentials expired", e);
        } catch (IncorrectCredentialsException e) {
            throw new InvalidCredentialsException("Invalid credentials", e);
        } catch (ExcessiveAttemptsException e) {
            throw new GrainSecurityException("Excessive attempts", e);
        } catch (LockedAccountException e) {
            throw new AccountLockedException("Account locked", e);
        } catch (ConcurrentAccessException e) {
            throw new GrainSecurityException("Concurrent access", e);
        } catch (UnknownAccountException e) {
            throw new UserNotFoundException("User not found", e);
        } catch (DisabledAccountException e) {
            throw new UserDisabledException("Account disabled", e);
        } catch (AuthenticationException e) {
            throw new GrainSecurityException("Authentication failed", e);
        }
    }
}
