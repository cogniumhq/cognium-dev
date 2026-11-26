// TP (CWE-614 / CWE-1004 / cognium-dev#118) — session cookie without Secure / HttpOnly flags.
package com.demo.fpcorpus;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
public class InsecureCookieTp {
    public void set(HttpServletResponse resp, String sid) {
        Cookie c = new Cookie("SESSIONID", sid);
        c.setSecure(false);    // SINK (CWE-614): not Secure
        c.setHttpOnly(false);  // SINK (CWE-1004): JS-readable
        resp.addCookie(c);
    }
}
