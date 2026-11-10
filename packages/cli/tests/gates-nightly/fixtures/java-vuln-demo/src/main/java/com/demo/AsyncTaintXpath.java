package com.demo;

import javax.xml.xpath.*;
import javax.servlet.http.HttpServletRequest;

/**
 * Combination #4 — ASYNCTAINT × XPATH (CWE-643).
 * A method with NO finding is a FALSE NEGATIVE (unless noted safe).
 */
public class AsyncTaintXpath {

    // 4. COMPLETABLEFUTURE — taint carried through async computation
    public void handle(HttpServletRequest req) throws Exception {
        String raw = req.getParameter("name");
        java.util.concurrent.CompletableFuture<String> f =
            java.util.concurrent.CompletableFuture.supplyAsync(() -> raw); // taint into future
        String name = f.get();
        XPathFactory.newInstance().newXPath().evaluate("//user[name='" + name + "']", (Object) null); // CWE-643
    }

}
