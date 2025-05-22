package store.account;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.server.ResponseStatusException;

import feign.FeignException;

@ControllerAdvice
public class StoreExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(StoreExceptionHandler.class);

    @ExceptionHandler(ResponseStatusException.class)
    private ResponseEntity<ProblemDetail> handle(ResponseStatusException e) {
        return ResponseEntity.status(e.getStatusCode()).body(e.getBody());
    }
    
    @ExceptionHandler(FeignException.class)
    private ResponseEntity<ProblemDetail> handle(FeignException e) {
        logger.debug("handle FeignException: " + e);
        HttpStatus code = HttpStatus.valueOf(e.status());
        String msg = e.getMessage();
        logger.debug("handle FeignException: (msg) " + msg);
        String details = Arrays.toString(e.getStackTrace());
        logger.debug("handle FeignException: (details) " + details);
        String ref = "\"title\":\"";
        int idxi = msg.indexOf(ref);
        if (idxi > -1) {
            idxi += ref.length();
            details = msg;
            msg = msg.substring(idxi, msg.indexOf("\"", idxi));
        }
        logger.debug("handle FeignException: (msg) " + msg);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(code, details);
        problemDetail.setTitle(msg);
        return ResponseEntity.status(code).body(problemDetail);
    }

}
