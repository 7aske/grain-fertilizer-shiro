package com._7aske.grain.fertilizer.proxy;

import com._7aske.grain.core.reflect.ProxyInterceptor;
import com._7aske.grain.logging.Logger;
import com._7aske.grain.logging.LoggerFactory;
import com._7aske.grain.security.exception.GrainSecurityException;
import net.bytebuddy.implementation.bind.annotation.*;
import net.bytebuddy.implementation.bytecode.ShiftLeft;

import java.lang.reflect.Method;

public class ShiroSecurityProxyInterceptor implements ProxyInterceptor {
    private final Logger logger = LoggerFactory.getLogger(ShiroSecurityProxyInterceptor.class);

    @Override
    @RuntimeType
    public Object intercept(@This Object self,
                            @Origin Method method,
                            @AllArguments Object[] args,
                            @SuperMethod(nullIfImpossible = true) Method superMethod) throws Throwable {
        logger.debug("Intercepting method " + method.getName());
        ShiroAnnotationChecker checker = new ShiroAnnotationChecker();

        if (!checker.canAccess(self, method)) {
            throw new GrainSecurityException("Access denied");
        }

        return method.invoke(self, args);
    }
}
