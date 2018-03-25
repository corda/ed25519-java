package net.i2p.crypto.eddsa.math.bigint;

import net.i2p.crypto.eddsa.math.EdDSAFiniteField;
import net.i2p.crypto.eddsa.math.EmptyEncoding;
import net.i2p.crypto.eddsa.math.FieldElement;
import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.util.Objects;

class MyEmptyEncoding extends EmptyEncoding {
    private final BigIntegerLittleEndianEncoding bigIntegerLittleEndianEncoding;

    public MyEmptyEncoding(BigIntegerLittleEndianEncoding bigIntegerLittleEndianEncoding) {
        this.bigIntegerLittleEndianEncoding = bigIntegerLittleEndianEncoding;
    }

    @Override
    public synchronized void setEdDSAFiniteField(@NotNull final EdDSAFiniteField f) {
        super.setEdDSAFiniteField(f);
        bigIntegerLittleEndianEncoding.setMask(BigInteger.ONE.shiftLeft(f.getb()-1).subtract(BigInteger.ONE));
    }

    public byte[] encode(@NotNull final FieldElement x) {
        return bigIntegerLittleEndianEncoding.convertBigIntegerToLittleEndian(((BigIntegerFieldElement)x).bi.and(bigIntegerLittleEndianEncoding.getMask()));
    }

    /**
     *  Decode a FieldElement from its $(b-1)$-bit encoding.
     *  The highest bit is masked out.
     *
     *  @param in the $(b-1)$-bit encoding of a FieldElement.
     *  @return the FieldElement represented by 'val'.
     *  @throws IllegalStateException if field not set
     *  @throws IllegalArgumentException if encoding is invalid
     */
    @NotNull
    public FieldElement decode(@NotNull final byte[] in) {
        Objects.requireNonNull(getEdDSAFiniteField(),"field not set");
        assert in.length == getEdDSAFiniteField().getb() / 8 : "Not a valid encoding";
        return new BigIntegerFieldElement(getEdDSAFiniteField(), bigIntegerLittleEndianEncoding.toBigInteger(in).and(bigIntegerLittleEndianEncoding.getMask()));
    }

    /**
     * From the Ed25519 paper:<br>
     * $x$ is negative if the $(b-1)$-bit encoding of $x$ is lexicographically larger
     * than the $(b-1)$-bit encoding of $-x$. If $q$ is an odd prime and the encoding
     * is the little-endian representation of $\{0, 1,\dots, q-1\}$ then the negative
     * elements of $F_q$ are $\{1, 3, 5,\dots, q-2\}$.
     * @return true if negative
     */
    public boolean isNegative(@NotNull final FieldElement x) {
        return ((BigIntegerFieldElement)x).bi.testBit(0);
    }
}
