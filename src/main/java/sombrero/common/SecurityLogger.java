package sombrero.common;

import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityLogger {

    public static void log(String message) {
        System.out.println("---------------------------------------------------");
        System.out.println("# " + message);
        Thread thread = Thread.currentThread();
        System.out.println("# thread.getName(): " + thread.getName());
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        System.out.println("# principal: " + principal);
        System.out.println("---------------------------------------------------");
    }

}
