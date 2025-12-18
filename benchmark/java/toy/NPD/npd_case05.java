public class NPDCase05 {

    public static void main(String[] args) {
        System.out.println("Starting Null Pointer Exception Demo.");
        
        // Step 1: Create an object that is null via an inter-procedural call.
        Object obj = case05_createObject();

        // Step 2: Process the object which propagates the null value.
        case05_processObject(obj);
    
    }

    // Function that simulates object creation but returns null.
    private static Object case05_createObject() {
        System.out.println("createObject: Calling getNullObject...");
        return case05_getNullObject();
    }

    // Helper function that explicitly returns null.
    private static Object case05_getNullObject() {
        System.out.println("getNullObject: Returning null.");
        return null;
    }

    // Function that further propagates the object received.
    private static void case05_processObject(Object obj) {
        System.out.println("processObject: Received object, calling useObject...");
        case05_useObject(obj);
    }
    
    // Function that uses the object, causing a Null Pointer Exception if object is null.
    private static void case05_useObject(Object obj) {
        System.out.println("useObject: Attempting to call toString on the object...");
        // This line will throw a NullPointerException if obj is null.
        System.out.println("Object's toString(): " + obj.toString());
    }
}