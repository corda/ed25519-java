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

import net.i2p.crypto.eddsa.math.EdDSAFiniteField;
import net.i2p.crypto.eddsa.math.ScalarOps;
import org.jetbrains.annotations.NotNull;

public class BigIntegerScalarOps implements ScalarOps {
    private final BigInteger l;
    @NotNull
    private final BigIntegerLittleEndianEncoding enc;

    public BigIntegerScalarOps(final EdDSAFiniteField f, final BigInteger l) {
        this.l = l;
        enc = new BigIntegerLittleEndianEncoding();
        enc.setEdDSAFiniteField(f);
    }

    public byte[] reduce(final byte[] s) {
        return enc.convertBigIntegerToLittleEndian(enc.toBigInteger(s).mod(l));
    }

    public byte[] multiplyAndAdd(final byte[] a, final byte[] b, final byte[] c) {
        return enc.convertBigIntegerToLittleEndian(enc.toBigInteger(a).multiply(enc.toBigInteger(b)).add(enc.toBigInteger(c)).mod(l));
    }

}
