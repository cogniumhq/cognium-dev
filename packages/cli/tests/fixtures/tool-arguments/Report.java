package tool;

import java.io.File;

public class Report {
    private File target;

    void setTarget(String name) {
        target = new File(name);
    }
}
