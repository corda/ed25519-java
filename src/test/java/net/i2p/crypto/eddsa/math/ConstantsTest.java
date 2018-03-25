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
package net.i2p.crypto.eddsa.math;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

import org.jetbrains.annotations.NotNull;
import org.junit.Test;

/**
 * Based on the tests in checkparams.py from the Python Ed25519 implementation.
 * @author str4d
 *
 */
public class ConstantsTest {
    private static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
    private static final Curve curve = ed25519.curve;

    private static final FieldElement ZERO = curve.getEdDSAFiniteField().ZERO;
    private static final FieldElement ONE = curve.getEdDSAFiniteField().ONE;
    static final FieldElement TWO = curve.getEdDSAFiniteField().TWO;

    static final GroupElement P3_ZERO = false ? new P3PreGroupElement(curve, ZERO, ONE, ONE, ZERO) : new P3GroupElement(curve, ZERO, ONE, ONE, ZERO);

    @Test
    public void testb() {
        final int b = curve.getEdDSAFiniteField().getb();
        assertThat(Integer.valueOf(b), is(greaterThanOrEqualTo(Integer.valueOf(10))));
        try {
            final MessageDigest h = MessageDigest.getInstance(ed25519.hashAlgo);
            assertThat(Integer.valueOf(8 * h.getDigestLength()), is(equalTo(Integer.valueOf(2 * b))));
        } catch (@NotNull final NoSuchAlgorithmException e) {
            fail(e.getMessage());
        }
    }

    /*@Test
    public void testq() {
        FieldElement q = curve.getEdDSAFiniteField().getQ();
        assertThat(TWO.modPow(q.subtractOne(), q), is(equalTo(ONE)));
        assertThat(q.mod(curve.getEdDSAFiniteField().FOUR), is(equalTo(ONE)));
    }

    @Test
    public void testl() {
        int b = curve.getEdDSAFiniteField().getb();
        BigInteger l = ed25519.getL();
        assertThat(TWO.modPow(l.subtract(BigInteger.ONE), l), is(equalTo(ONE)));
        assertThat(l, is(greaterThanOrEqualTo(BigInteger.valueOf(2).pow(b-4))));
        assertThat(l, is(lessThanOrEqualTo(BigInteger.valueOf(2).pow(b-3))));
    }

    @Test
    public void testd() {
        FieldElement q = curve.getEdDSAFiniteField().getQ();
        FieldElement qm1 = q.subtractOne();
        assertThat(curve.getD().modPow(qm1.divide(curve.getEdDSAFiniteField().TWO), q), is(equalTo(qm1)));
    }

    @Test
    public void testI() {
        FieldElement q = curve.getEdDSAFiniteField().getQ();
        assertThat(curve.getFieldElementI().modPow(curve.getEdDSAFiniteField().TWO, q), is(equalTo(q.subtractOne())));
    }*/

    @Test
    public void testB() {
        final GroupElement B = ed25519.groupElement;
        assertThat(Boolean.valueOf(B.isOnCurve(curve)), is(Boolean.TRUE));
        //assertThat(B.scalarMultiply(new BigIntegerLittleEndianEncoding().encode(ed25519.getL(), curve.getEdDSAFiniteField().getb()/8)), is(equalTo(P3_ZERO)));
    }
}
