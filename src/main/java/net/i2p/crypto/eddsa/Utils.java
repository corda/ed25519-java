/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Basic utilities for EdDSA.
 * Not for external use, not maintained as a public API.
 *
 * @author str4d
 *
 */
public class Utils {
    /**
     * Constant-time byte comparison.
     * @param b a byte
     * @param c a byte
     * @return 1 if b and c are equal, 0 otherwise.
     */
    public static int equal(final int b, final int c) {
        int result = 0;
        final int xor = b ^ c;
        result |= xor >> 0;
        result |= xor >> 1;
        result |= xor >> 2;
        result |= xor >> 3;
        result |= xor >> 4;
        result |= xor >> 5;
        result |= xor >> 6;
        result |= xor >> 7;
        return (result ^ 0x01) & 0x01;
    }

    /**
     * Constant-time byte[] comparison.
     * @param b a byte[]
     * @param c a byte[]
     * @return 1 if b and c are equal, 0 otherwise.
     */
    public static int equal(final byte[] b, final byte[] c) {
        int result = 0;
        result |= b[0] ^ c[0];
        result |= b[1] ^ c[1];
        result |= b[2] ^ c[2];
        result |= b[3] ^ c[3];
        result |= b[4] ^ c[4];
        result |= b[5] ^ c[5];
        result |= b[6] ^ c[6];
        result |= b[7] ^ c[7];
        result |= b[8] ^ c[8];
        result |= b[9] ^ c[9];
        result |= b[10] ^ c[10];
        result |= b[11] ^ c[11];
        result |= b[12] ^ c[12];
        result |= b[13] ^ c[13];
        result |= b[14] ^ c[14];
        result |= b[15] ^ c[15];
        result |= b[16] ^ c[16];
        result |= b[17] ^ c[17];
        result |= b[18] ^ c[18];
        result |= b[19] ^ c[19];
        result |= b[20] ^ c[20];
        result |= b[21] ^ c[21];
        result |= b[22] ^ c[22];
        result |= b[23] ^ c[23];
        result |= b[24] ^ c[24];
        result |= b[25] ^ c[25];
        result |= b[26] ^ c[26];
        result |= b[27] ^ c[27];
        result |= b[28] ^ c[28];
        result |= b[29] ^ c[29];
        result |= b[30] ^ c[30];
        result |= b[31] ^ c[31];

        return equal(result, 0);
    }

    /**
     * Constant-time determine if byte is negative.
     * @param b the byte to check.
     * @return 1 if the byte is negative, 0 otherwise.
     */
    public static int negative(final int b) {
        return (b >> 8) & 1;
    }

    /**
     * Get the i'th bit of a byte array.
     * @param h the byte array.
     * @param i the bit index.
     * @return 0 or 1, the value of the i'th bit in h
     */
    public static int bit(final byte[] h, final int i) {
        return (h[i >> 3] >> (i & 7)) & 1;
    }

    /**
     * Converts a hex string to bytes.
     * @param s the hex string to be converted.
     * @return the byte[]
     */
    @NotNull
    public static byte[] hexToBytes(final CharSequence s) {
        final int len = s.length();
        @NotNull final byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Converts bytes to a hex string.
     * @param raw the byte[] to be converted.
     * @return the hex representation as a string.
     */
    @Nullable
    public static String bytesToHex(@Nullable final byte[] raw) {
        if (null == raw) {
            return null;
        }
        @NotNull final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(Character.forDigit(((int) b & 0xF0) >> 4, 16))
            .append(Character.forDigit(((int) b & 0x0F), 16));
        }
        return hex.toString();
    }

}
