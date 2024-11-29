package com._7aske.grain.fertilizer.proxy;

import com._7aske.grain.annotation.Nullable;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.*;
import org.apache.shiro.subject.Subject;

import java.lang.reflect.Method;
import java.util.Arrays;

public class ShiroAnnotationChecker {
    public boolean canAccess(Object self, Method method) {
        Subject subject = SecurityUtils.getSubject();

        if (!checkGuest(subject, self.getClass().getAnnotation(RequiresGuest.class))) {
            return false;
        }

        if (!checkAuthenticated(subject, self.getClass().getAnnotation(RequiresAuthentication.class))) {
            return false;
        }

        if (!checkUser(subject, self.getClass().getAnnotation(RequiresUser.class))) {
            return false;
        }

        if (!checkRoles(subject, self.getClass().getAnnotation(RequiresRoles.class))) {
            return false;
        }

        if (!checkPermissions(subject, self.getClass().getAnnotation(RequiresPermissions.class))) {
            return false;
        }

        if (!checkGuest(subject, method.getAnnotation(RequiresGuest.class))) {
            return false;
        }

        if (!checkAuthenticated(subject, method.getAnnotation(RequiresAuthentication.class))) {
            return false;
        }

        if (!checkUser(subject, method.getAnnotation(RequiresUser.class))) {
            return false;
        }

        if (!checkRoles(subject, method.getAnnotation(RequiresRoles.class))) {
            return false;
        }

        if (!checkPermissions(subject, method.getAnnotation(RequiresPermissions.class))) {
            return false;
        }

        return true;
    }

    private boolean checkRoles(Subject subject, @Nullable RequiresRoles roles) {
        if (roles == null) {
            return true;
        }

        if (roles.logical().equals(Logical.AND)) {
            return subject.hasAllRoles(Arrays.asList(roles.value()));
        }

        return Arrays.stream(roles.value()).anyMatch(subject::hasRole);
    }

    private boolean checkAuthenticated(Subject subject, @Nullable RequiresAuthentication annotation) {
        if (annotation == null) {
            return true;
        }

        return subject.isAuthenticated();
    }

    private boolean checkGuest(Subject subject, @Nullable RequiresGuest annotation) {
        if (annotation == null) {
            return true;
        }

        return subject == null || !subject.isAuthenticated();
    }

    private boolean checkPermissions(Subject subject, @Nullable RequiresPermissions annotation) {
        if (annotation == null) {
            return true;
        }

        if (annotation.logical().equals(Logical.AND)) {
            return subject.isPermittedAll(annotation.value());
        }

        return Arrays.stream(annotation.value()).anyMatch(subject::isPermitted);
    }

    private boolean checkUser(Subject subject, @Nullable RequiresUser annotation) {
        if (annotation == null) {
            return true;
        }

        return subject.getPrincipal() != null;
    }
}
