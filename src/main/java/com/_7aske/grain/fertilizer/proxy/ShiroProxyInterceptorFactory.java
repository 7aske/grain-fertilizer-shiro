package com._7aske.grain.fertilizer.proxy;

import com._7aske.grain.core.reflect.ProxyInterceptor;
import com._7aske.grain.core.reflect.ProxyInterceptorAbstractFactory;
import com._7aske.grain.core.reflect.ReflectionUtil;
import org.apache.shiro.authz.annotation.*;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.List;

public class ShiroProxyInterceptorFactory implements ProxyInterceptorAbstractFactory {
    private static List<Class<? extends Annotation>> SUPPORTED = List.of(
            RequiresAuthentication.class,
            RequiresUser.class,
            RequiresPermissions.class,
            RequiresRoles.class,
            RequiresGuest.class
    );

    @Override
    public <T> Class<T> getDiscriminatorType() {
        return null;
    }

    @Override
    public boolean supports(Object object) {
        if (object instanceof Class<?> clazz) {
            return SUPPORTED.stream().anyMatch(annotation -> ReflectionUtil.isAnnotationPresent(clazz, annotation));
        }

        if (object instanceof Method method) {
            return SUPPORTED.stream().anyMatch(annotation -> {
                boolean classAnnotated = ReflectionUtil.isAnnotationPresent(method.getDeclaringClass(), annotation);
                boolean methodAnnotated = ReflectionUtil.isAnnotationPresent(method, annotation);
                return classAnnotated || methodAnnotated;
            });
        }

        return false;
    }

    @Override
    public ProxyInterceptor create(Method method) {
        return new ShiroSecurityProxyInterceptor();
    }
}
