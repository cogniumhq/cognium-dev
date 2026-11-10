import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class TaskServletSafe extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request) throws IOException {
        String job = request.getParameter("job");
        TaskLine line = new TaskLine("git");
        line.addArgument("log");
        line.addArgument(job);
        line.execute();
    }
}
