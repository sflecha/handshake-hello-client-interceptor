package sflecha.handshakehelloclientinterceptor.web;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.Map;

@Controller
@Slf4j
public class HelloController {

    @GetMapping(value = "/hello")
    public ResponseEntity<?> getHello(@RequestHeader Map<String, String> headers) {

        log.info("hello controller called");

        return new ResponseEntity<>(headers, HttpStatus.OK);

    }


}
