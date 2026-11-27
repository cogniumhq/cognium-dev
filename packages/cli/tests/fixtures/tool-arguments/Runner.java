package tool;

import java.io.FileInputStream;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;

public class Runner {
    public static void main(String[] args) throws Exception {
        FileInputStream config = new FileInputStream(args[0]);
        Options options = new Options();
        CommandLineParser parser = new DefaultParser();
        CommandLine line = parser.parse(options, args);
        new Report().setTarget(line.getOptionValue("f"));
    }
}
