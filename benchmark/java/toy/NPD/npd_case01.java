public public class NPDCase01 {
    public static Object case01_getObj() {
        return null;
    }
    public static int case01_useObj() {
        Object obj = case01_getObj();
        return obj.hashCode();
    }
    
    public static void main(String[] args) {
        case01_useObj();
    }
}
