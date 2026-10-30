/** A small Java service for the Java graph-facts tests. */

export const JAVA_APP: Record<string, string> = {
  'src/main/java/app/web/UserController.java': `package app.web;

import app.core.UserService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {
  private final UserService service;

  public UserController(UserService service) { this.service = service; }

  @GetMapping("/{id}")
  public String get(@PathVariable String id) { return service.find(id); }

  @RequestMapping(value = {"", "/all"}, method = {RequestMethod.GET, RequestMethod.HEAD})
  public String list() { return service.all(); }
}
`,
  'src/main/java/app/core/UserService.java': `package app.core;

import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class UserService {
  private final Store store = new MemStore();

  public String find(String id) { return store.load(id); }
  public String all() { return String.join(",", List.of("a", "b").stream().map(this::format).toList()); }
  String format(String s) { return s.trim(); }
  public String unused() { return "x"; }
  public String onlyTested() { return "t"; }
}
`,
  'src/main/java/app/core/Store.java': `package app.core;

public interface Store {
  String load(String id);
}
`,
  'src/main/java/app/core/MemStore.java': `package app.core;

public class MemStore implements Store {
  public String load(String id) { return id; }
  void legacy() {}
}
`,
  'src/main/java/app/core/DbStore.java': `package app.core;

public class DbStore implements Store {
  public String load(String id) { return "db:" + id; }
}
`,
  'src/main/java/app/api/Health.java': `package app.api;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

@Path("/health")
public class Health {
  @GET
  public String ok() { return "ok"; }

  @GET
  @Path("/deep")
  public String deep() { return "deep"; }
}
`,
  'src/main/java/app/servlet/Legacy.java': `package app.servlet;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.*;

@WebServlet(urlPatterns = "/legacy")
public class Legacy extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) {}
  public void init() {}
}

class Audit implements Filter {
  public void doFilter(ServletRequest a, ServletResponse b, FilterChain c) {}
}
`,
  'src/main/java/app/Main.java': `package app;

public class Main {
  public static void main(String[] args) throws Exception {
    Object plugin = Class.forName("app.plugins.Echo").getDeclaredConstructor().newInstance();
    Runnable r = () -> System.out.println(plugin);
    r.run();
  }
}
`,
  'src/main/java/app/plugins/Echo.java': `package app.plugins;

public class Echo {
  public Echo() {}
}
`,
  'src/main/java/app/plugins/Spi.java': `package app.plugins;

public class Spi {
  public void hook() {}
}
`,
  'src/test/java/app/core/UserServiceTest.java': `package app.core;

import org.junit.jupiter.api.Test;

class UserServiceTest {
  @Test
  void tested() { new UserService().onlyTested(); }
}
`,
};
