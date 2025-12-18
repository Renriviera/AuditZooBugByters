public class NPDCase04 {
    public static String[] case04_getArray() {
        return new String[] { "Hello", null, "World" };
    }
    public static int case04_useArray() {
        String[] arr = case04_getArray();
        return arr[1].length();
    }
    
    public static void main(String[] args) {
        case04_useArray();
    }
}