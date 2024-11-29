package com._7aske.grain.fertilizer.shiro;

import com._7aske.grain.core.component.Order;
import com._7aske.grain.security.exception.GrainSecurityException;
import com._7aske.grain.web.controller.annotation.Controller;
import com._7aske.grain.web.controller.annotation.GetMapping;
import com._7aske.grain.web.controller.annotation.PostMapping;
import com._7aske.grain.web.controller.annotation.RequestMapping;
import com._7aske.grain.web.http.HttpRequest;
import com._7aske.grain.web.http.HttpResponse;
import com._7aske.grain.web.ui.LoginPage;
import com._7aske.grain.web.view.View;

/**
 * Default authentication entry point handling form POST requests to /login
 */
@Controller
@Order(Order.LOWEST_PRECEDENCE - 100)
@RequestMapping
public class ShiroAuthenticationEntryPointController {
    private final ShiroFormLoginAuthenticationEntryPoint entryPoint;
    private final LoginPage loginPage;

    public ShiroAuthenticationEntryPointController(
            ShiroFormLoginAuthenticationEntryPoint entryPoint,
            LoginPage loginPage) {
        this.entryPoint = entryPoint;
        this.loginPage = loginPage;
    }

    // @Todo handle redirect after successful or unsuccessful login
    @PostMapping("/login")
    public String postLogin(HttpRequest request, HttpResponse response) {
        try {
            entryPoint.authenticate(request, response);
            return "redirect:" + "/";
        } catch (GrainSecurityException e) {
            return "redirect:" + "/login" + "?error";
        }
    }

    @GetMapping("/login")
    public View getLogin() {
        return loginPage;
    }

    // TODO: handle logout
}
