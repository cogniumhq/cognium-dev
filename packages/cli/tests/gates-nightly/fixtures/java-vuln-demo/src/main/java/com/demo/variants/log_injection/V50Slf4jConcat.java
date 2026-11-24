package com.demo.variants.log_injection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;

public class V50Slf4jConcat {
    private static final Logger log = LoggerFactory.getLogger(V50Slf4jConcat.class);
    public void audit(HttpServletRequest req) {
        String user = req.getParameter("user");
        log.info("login attempt for user=" + user);
    }
}