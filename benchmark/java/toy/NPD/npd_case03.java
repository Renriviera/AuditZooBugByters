public class NPDCase03 {
    public static String case03_getData() {
        return null;
    }
    public static String case03_transformData(String data) {
        return data.toUpperCase();
    }
    public static String case03_main() {
        String data = case03_getData();
        return case03_transformData(data);
    }
    
    public static void main(String[] args) {
        case03_main();
    }
}