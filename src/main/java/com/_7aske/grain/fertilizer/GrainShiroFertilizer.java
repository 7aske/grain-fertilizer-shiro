package com._7aske.grain.fertilizer;

import com._7aske.grain.core.component.ConditionalOnMissingGrain;
import com._7aske.grain.core.component.Grain;
import com._7aske.grain.core.component.Order;
import com._7aske.grain.core.configuration.GrainFertilizer;
import com._7aske.grain.core.reflect.ProxyInterceptorAbstractFactory;
import com._7aske.grain.fertilizer.proxy.ShiroProxyInterceptorFactory;
import com._7aske.grain.fertilizer.shiro.crypto.MessageDigestPasswordService;
import com._7aske.grain.fertilizer.shiro.realm.UserServiceRealm;
import com._7aske.grain.logging.Logger;
import com._7aske.grain.logging.LoggerFactory;
import com._7aske.grain.security.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.env.DefaultEnvironment;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.eis.MemorySessionDAO;
import org.apache.shiro.session.mgt.eis.SessionDAO;

import java.security.NoSuchAlgorithmException;

@GrainFertilizer
public class GrainShiroFertilizer {
    private final Logger logger = LoggerFactory.getLogger(GrainShiroFertilizer.class);

    @Grain
    @Order
    public ProxyInterceptorAbstractFactory shiroProxyInterceptorFactory() {
        return new ShiroProxyInterceptorFactory();
    }

    @Grain
    @ConditionalOnMissingGrain(SessionDAO.class)
    public SessionDAO defaultSessionDAO() {
        return new MemorySessionDAO();
    }

    @Grain
    @ConditionalOnMissingGrain(Environment.class)
    public Environment defaultEnvironment() {
        return new DefaultEnvironment();
    }

    @Grain
    @ConditionalOnMissingGrain(Realm.class)
    public Realm defaultRealm(UserService userService) throws NoSuchAlgorithmException {
        logger.info("Creating default realm");
        UserServiceRealm aDefault = new UserServiceRealm(userService, "default");
        PasswordMatcher passwordMatcher = new PasswordMatcher();
        passwordMatcher.setPasswordService(new MessageDigestPasswordService());
        aDefault.setCredentialsMatcher(passwordMatcher);
        return aDefault;
    }

    @Grain
    @ConditionalOnMissingGrain(SecurityManager.class)
    public SecurityManager defaultSecurityManager(SessionDAO sessionDAO, Realm realm) {
        logger.info("Creating default security manager");
        SecurityManager securityManager = new DefaultSecurityManager(realm);
        SecurityUtils.setSecurityManager(securityManager);
        return securityManager;
    }
}
