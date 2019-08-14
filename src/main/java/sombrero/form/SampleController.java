package sombrero.form;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class SampleController {

    @Autowired
    SampleService sampleService;

    /**
     * index 페이지
     * (로그인한 사용자와 로그인하지 않은 사용자에 따라 첫페이지를 다르게 보이고 싶을 경우 principal 추가.)
     * (인덱스 페이지는 permitAll()로 설정했기 때문에 principal이 없어도 접근 가능. NullPointerException이 발생하지 않음.)
     */
    @GetMapping("/")
    public String index(Model model, Principal principal) {
        if(principal ==  null) {
            model.addAttribute("message", "Hello Spring Security");
        } else {
            model.addAttribute("message", "Hello, " + principal.getName());
        }

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
     * (로그인하여 principal이 있어야 접근 가능한 페이지, principal이 없으면 null이 들어와서 NullPointerException 발생.)
     */
    @GetMapping("/dashboard")
    public String dashboard(Model model, Principal principal) {
        model.addAttribute("message", "Hello " + principal.getName());
        sampleService.dashboard();
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
