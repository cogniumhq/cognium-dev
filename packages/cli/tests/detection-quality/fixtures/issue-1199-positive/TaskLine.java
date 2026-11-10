import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class TaskLine {
    private String executable;
    private final List<String> arguments = new ArrayList<>();

    public TaskLine(String executable) {
        this.executable = executable;
    }

    public void setExecutable(String executable) {
        this.executable = executable;
    }

    public void addArgument(String argument) {
        this.arguments.add(argument);
    }

    public Process execute() throws IOException {
        List<String> argv = new ArrayList<>();
        argv.add(executable);
        argv.addAll(arguments);
        return new ProcessBuilder(argv).start(); // SINK_LINE
    }
}
