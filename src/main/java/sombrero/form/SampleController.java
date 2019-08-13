package sombrero.form;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class SampleController {

    /**
     * index 페이지
     */
    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("message", "Hello Spring Security");
        return "index";
    }

    /**
     * 로그인하지 않아도 볼 수 있는 info 페이지
     */
    @GetMapping("/info")
    public String info(Model model) {
        model.addAttribute("message", "info");
        return "info";
    }

    /**
     * 로그인한 사용자만 볼 수 있는 dashboard 페이지
     * (로그인하여 principal이 있어야 접근 가능한 페이지)
     */
    @GetMapping("/dashboard")
    public String dashboard(Model model, Principal principal) {
        model.addAttribute("message", "Hello " + principal.getName());
        return "dashboard";
    }

    /**
     * 관리자 권한으로 로그인한 사용자만 볼 수 있는 admin 페이지
     */
    @GetMapping("/admin")
    public String admin(Model model, Principal principal) {
        model.addAttribute("message", "Hello admin, " + principal.getName());
        return "admin";
    }

}
