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
package net.i2p.crypto.eddsa.math.ed25519;

import net.i2p.crypto.eddsa.math.*;
import org.jetbrains.annotations.NotNull;

/**
 * Helper class for encoding/decoding from/to the 32 byte representation.
 * <p>
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 */
public class Ed25519LittleEndianEncoding {

    public final MyEmptyEncoding emptyEncoding = new MyEmptyEncoding(this);

    static int load_3(final byte[] in, int offset) {
        int offset1 = offset;
        int result = in[offset1++] & 0xff;
        result |= (in[offset1++] & 0xff) << 8;
        result |= (in[offset1] & 0xff) << 16;
        return result;
    }

    static long load_4(final byte[] in, int offset) {
        int offset1 = offset;
        int result = in[offset1++] & 0xff;
        result |= (in[offset1++] & 0xff) << 8;
        result |= (in[offset1++] & 0xff) << 16;
        result |= in[offset1] << 24;
        return ((long)result) & 0xffffffffL;
    }

    @NotNull
    public EmptyEncoding getEmptyEncoding() {
        return emptyEncoding;
    }

    public void setEdDSAFiniteField(final EdDSAFiniteField f) {
        emptyEncoding.setEdDSAFiniteField(f);
    }

    public EdDSAFiniteField getEdDSAFiniteField() {
        return emptyEncoding.getEdDSAFiniteField();
    }

}
