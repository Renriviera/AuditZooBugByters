public class NPDCase02 {
    public static int case02_process(String data) {
        return data.length();
    }
    public static int case02_caller() {
        String data = null;
        return case02_process(data);
    }
    
    public static void main(String[] args) {
        case02_caller();
    }
}