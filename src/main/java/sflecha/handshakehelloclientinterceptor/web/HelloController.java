package sflecha.handshakehelloclientinterceptor.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.Map;

@Controller
public class HelloController {

    private static final Logger logger = LoggerFactory.getLogger(HelloController.class);

    @GetMapping(value = "/hello")
    public ResponseEntity<?> getHello(@RequestHeader Map<String, String> headers) {

        logger.info("test controller called");

        return new ResponseEntity<>(headers, HttpStatus.OK);

    }


}
