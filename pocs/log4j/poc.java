import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;


public class poc {
    private static Logger log = LogManager.getLogger();

    public static void main(String[] args) {
	    ThreadContext.put("user",args[0]);
	    log.fatal("\n\n\n\n\noh hai there\n\n\n\n\n");
    }
}
