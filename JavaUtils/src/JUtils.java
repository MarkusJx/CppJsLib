import org.graalvm.nativeimage.IsolateThread;
import org.graalvm.nativeimage.c.function.CEntryPoint;
import org.graalvm.word.Pointer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;

// Suppress unused warnings as almost everything in here will be unused
@SuppressWarnings("unused")
public class JUtils {

    public static void main(String[] args) throws Exception {
        throw new Exception("Main function does not do anything");
    }

    /**
     * Convert c pointer to byte array
     *
     * @param arr the pointer
     * @param len the array length
     * @return the resulting byte array
     */
    private static byte[] cPointerToByteArray(Pointer arr, int len) {
        // Read individual bytes into byte buffer
        byte[] bytes = new byte[len];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = arr.readByte(i);
        }

        return bytes;
    }

    /**
     * Convert c char pointer to string
     *
     * @param arr the pointer to the char array
     * @return the resulting string
     */
    private static String parseCCharArray(Pointer arr) {
        // Determine string length by searching for null byte
        int len = 0;
        while (arr.readByte(len) != 0x0) len++;

        // Create string from bytes (using ASCII charset) and return it
        return new String(cPointerToByteArray(arr, len), StandardCharsets.US_ASCII);
    }

    @CEntryPoint(name = "portInUse")
    public static boolean portInUse(IsolateThread thread, Pointer address, int port) {
        try {
            ServerSocket ss = new ServerSocket(port, 50, InetAddress.getByName(parseCCharArray(address)));
            ss.close();
        } catch (IOException e) {
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
