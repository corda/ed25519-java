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
package net.i2p.crypto.eddsa.math.bigint;

import java.math.BigInteger;
import java.util.Objects;

import net.i2p.crypto.eddsa.math.EmptyEncoding;
import net.i2p.crypto.eddsa.math.EdDSAFiniteField;
import org.jetbrains.annotations.NotNull;

class BigIntegerLittleEndianEncoding {

    private final MyEmptyEncoding emptyEncoding = new MyEmptyEncoding(this);
    private BigInteger mask;

    /**
     *  Convert $x$ to little endian.
     *  Constant time.
     *
     *  @param x the BigInteger value to encode
     *  @return array of length $b/8$
     *  @throws IllegalStateException if field not set
     */
    @NotNull
    public byte[] convertBigIntegerToLittleEndian(@NotNull final BigInteger x) {
        Objects.requireNonNull(getEdDSAFiniteField(),"field not set");
        final byte[] in = x.toByteArray();
        @NotNull final byte[] out = new byte[getEdDSAFiniteField().getb()/8];
        final int bound = in.length;
        for (int i1 = 0; i1 < bound; i1++) {
            out[i1] = in[in.length - 1 - i1];
        }
        final int bound1 = out.length;
        for (int i = in.length; i < bound1; i++) {
            out[i] = (byte) 0;
        }
        return out;
    }

    /**
     *  Convert in to big endian
     *
     *  @param in the $(b-1)$-bit encoding of a FieldElement.
     *  @return the decoded value as a BigInteger
     */
    @NotNull
    public BigInteger toBigInteger(@NotNull final byte[] in) {
        @NotNull final byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length-1-i];
        }
        return new BigInteger(1, out);
    }

    @NotNull
    public EmptyEncoding getEmptyEncoding() {
        return emptyEncoding;
    }

    public void setEdDSAFiniteField(@NotNull final EdDSAFiniteField f) {
        emptyEncoding.setEdDSAFiniteField(f);
    }

    private EdDSAFiniteField getEdDSAFiniteField() {
        return emptyEncoding.getEdDSAFiniteField();
    }

    /**
     * Mask where only the first b-1 bits are set.
     */
    public BigInteger getMask() {
        return mask;
    }

    public void setMask(BigInteger mask) {
        this.mask = mask;
    }
}
