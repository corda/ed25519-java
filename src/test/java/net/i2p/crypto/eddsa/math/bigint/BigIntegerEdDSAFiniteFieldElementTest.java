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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.*;
import org.jetbrains.annotations.NotNull;
import org.junit.Test;

/**
 * @author str4d
 *
 */
public class BigIntegerEdDSAFiniteFieldElementTest extends AbstractEdDSAFiniteFieldElementTest {
    private static final byte[] BYTES_ZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] BYTES_ONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] BYTES_TEN = Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000000");

    private static final EdDSAFiniteField ED_25519_ED_DSA_FINITE_FIELD = new EdDSAFiniteField(
            256, // b
            Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
            new BigIntegerLittleEndianEncoding().getEmptyEncoding());

    private static final FieldElement ZERO = new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ZERO);
    private static final FieldElement ONE = new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ONE);
    private static final FieldElement TWO = new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(2L));

    @NotNull
    protected FieldElement getRandomFieldElement() {
        BigInteger r;
        @NotNull final Random rnd = new SecureRandom( );
        do {
            r = new BigInteger(255, rnd);
        } while (0 <= r.compareTo(getQ()));
        return new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, r);
    }

    protected BigInteger toBigInteger(@NotNull final FieldElement f) {
        return ((BigIntegerFieldElement)f).bi;
    }

    @NotNull
    protected BigInteger getQ() {
        return MathUtils.getQ();
    }

    @NotNull
    protected EdDSAFiniteField getEdDSAFiniteField() {
        return ED_25519_ED_DSA_FINITE_FIELD;
    }

    /**
     * Test method for {@link BigIntegerFieldElement#BigIntegerFieldElement(EdDSAFiniteField, BigInteger)}.
     */
    @Test
    public void testFieldElementBigInteger() {
        assertThat(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ZERO).bi, is(BigInteger.ZERO));
        assertThat(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ONE).bi, is(BigInteger.ONE));
        assertThat(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(2L)).bi, is(BigInteger.valueOf(2L)));
    }

    /**
     * Test method for {@link BaseFieldElement#toByteArray()}.
     */
    @Test
    public void testToByteArray() {
        final byte[] zero = ZERO.toByteArray();
        assertThat(Integer.valueOf(zero.length), is(equalTo(Integer.valueOf(BYTES_ZERO.length))));
        assertThat(zero, is(equalTo(BYTES_ZERO)));

        final byte[] one = ONE.toByteArray();
        assertThat(Integer.valueOf(one.length), is(equalTo(Integer.valueOf(BYTES_ONE.length))));
        assertThat(one, is(equalTo(BYTES_ONE)));

        final byte[] ten = new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.TEN).toByteArray();
        assertThat(Integer.valueOf(ten.length), is(equalTo(Integer.valueOf(BYTES_TEN.length))));
        assertThat(ten, is(equalTo(BYTES_TEN)));
    }

    // region isNonZero

    @NotNull
    protected FieldElement getZeroFieldElement() {
        return ZERO;
    }

    @NotNull
    protected FieldElement getNonZeroFieldElement() {
        return TWO;
    }

    // endregion

    /**
     * Test method for {@link BaseFieldElement#equals(java.lang.Object)}.
     */
    @Test
    public void testEqualsObject() {
        assertThat(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.ZERO), is(equalTo(ZERO)));
        assertThat(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(1000L)), is(equalTo(new BigIntegerFieldElement(ED_25519_ED_DSA_FINITE_FIELD, BigInteger.valueOf(1000L)))));
        assertThat(ONE, is(not(equalTo(TWO))));
    }

}
