package cu.entalla.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("/helloTest")
    public String sayHello() {

        return "¡Hola desde wso2-client en modo de prueba!";
    }
}
