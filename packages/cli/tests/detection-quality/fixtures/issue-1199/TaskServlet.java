import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class TaskServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request) throws IOException {
        String job = request.getParameter("job");
        TaskLine line = new TaskLine("/bin/sh");
        line.addArgument("-c");
        line.addArgument("run " + job);
        line.execute();
    }
}
