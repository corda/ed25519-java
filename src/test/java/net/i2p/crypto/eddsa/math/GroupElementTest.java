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

import net.i2p.crypto.eddsa.*;
import net.i2p.crypto.eddsa.spec.*;
import org.hamcrest.core.*;
import org.jetbrains.annotations.NotNull;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Iterator;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * @author str4d
 * Additional tests by NEM project team.
 *
 */
public class GroupElementTest {
    private static final byte[] BYTES_ZEROZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] BYTES_ONEONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000080");
    private static final byte[] BYTES_TENZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] BYTES_ONETEN = Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000080");

    private static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
    private static final Curve curve = ed25519.curve;

    private static final FieldElement ZERO = curve.getEdDSAFiniteField().ZERO;
    private static final FieldElement ONE = curve.getEdDSAFiniteField().ONE;
    private static final FieldElement TWO = curve.getEdDSAFiniteField().TWO;
    private static final FieldElement TEN = curve.getEdDSAFiniteField().fromByteArray(Utils.hexToBytes("0a00000000000000000000000000000000000000000000000000000000000000"));

    private static final GroupElement P2_ZERO = new P2GroupElement(curve, ZERO, ONE, ONE);

    private static final FieldElement[] PKR = {
        curve.getEdDSAFiniteField().fromByteArray(Utils.hexToBytes("5849722e338aced7b50c7f0e9328f9a10c847b08e40af5c5b0577b0fd8984f15")),
        curve.getEdDSAFiniteField().fromByteArray(Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"))
        };
    private static final byte[] BYTES_PKR = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");

    @NotNull
    @Rule
    public ExpectedException exception = ExpectedException.none();

    /**
     * Negates a group element.
     *
     * @param g The group element.
     * @return The negated group element.
     */
    private static GroupElement negateGroupElement(final GroupElement g) {
        if (Representation.P3 != g.getRepresentation()) {
            throw new IllegalArgumentException("g must have representation P3");
        }

        final Curve curve1 = g.getCurve();
        final FieldElement x = g.getX().negate();
        final FieldElement y = g.getY();
        final FieldElement z = g.getZ();
        final FieldElement t = g.getT().negate();
        /**
     * Creates a new group element in P3 representation.
     *
     * @param curve The curve.
     * @param X The $X$ coordinate.
     * @param Y The $Y$ coordinate.
     * @param Z The $Z$ coordinate.
     * @param T The $T$ coordinate.
     * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
     * @return The group element in P3 representation.
     */
        return false ? new P3PreGroupElement(curve1, x, y, z, t) : new P3GroupElement(curve1, x, y, z, t);
    }

    /**
     * Calculates f1 * g1 + f2 * g2.
     *
     * @param g1 The first group element.
     * @param f1 The first multiplier.
     * @param g2 The second group element.
     * @param f2 The second multiplier.
     * @return The resulting group element.
     */
    private static GroupElement doubleScalarMultiplyGroupElements(
            @NotNull final GroupElement g1,
            @NotNull final FieldElement f1,
            @NotNull final GroupElement g2,
            @NotNull final FieldElement f2) {
        final GroupElement h1 = MathUtils.scalarMultiplyGroupElement(g1, f1);
        final GroupElement h2 = MathUtils.scalarMultiplyGroupElement(g2, f2);
        return MathUtils.addGroupElements(h1, h2);
    }

    /**
     * Creates a group element from a byte array.
     * <p>
     * Bit 0 to 254 are the affine y-coordinate, bit 255 is the sign of the affine x-coordinate.
     *
     * @param bytes the byte array.
     * @return The group element.
     */
    private static GroupElement toGroupElement(final byte[] bytes) {
        final boolean shouldBeNegative = 0 != (bytes[31] >> 7);
        bytes[31] = (byte) (bytes[31] & 0x7f);
        final BigInteger y = MathUtils.toBigInteger(bytes);

        // x = sign(x) * sqrt((y^2 - 1) / (d * y^2 + 1))
        final BigInteger u = y.multiply(y).subtract(BigInteger.ONE).mod(MathUtils.getQ());
        final BigInteger v = MathUtils.d.multiply(y).multiply(y).add(BigInteger.ONE).mod(MathUtils.getQ());
        final BigInteger tmp = u.multiply(v.pow(7)).modPow(BigInteger.ONE.shiftLeft(252).subtract(new BigInteger("3")), MathUtils.getQ()).mod(MathUtils.getQ());
        BigInteger x = tmp.multiply(u).multiply(v.pow(3)).mod(MathUtils.getQ());
        if (!v.multiply(x).multiply(x).subtract(u).mod(MathUtils.getQ()).equals(BigInteger.ZERO)) {
            if (!v.multiply(x).multiply(x).add(u).mod(MathUtils.getQ()).equals(BigInteger.ZERO)) {
                throw new IllegalArgumentException("not a valid GroupElement");
            }
            x = x.multiply(MathUtils.toBigInteger(MathUtils.curve.getFieldElementI())).mod(MathUtils.getQ());
        }
        final boolean isNegative = x.mod(new BigInteger("2")).equals(BigInteger.ONE);
        if ((shouldBeNegative && !isNegative) || (!shouldBeNegative && isNegative)) {
            x = x.negate().mod(MathUtils.getQ());
        }

        @NotNull final FieldElement x1 = MathUtils.toFieldElement(x);
        @NotNull final FieldElement y1 = MathUtils.toFieldElement(y);
        @NotNull final FieldElement t = MathUtils.toFieldElement(x.multiply(y).mod(MathUtils.getQ()));
        /**
     * Creates a new group element in P3 representation.
     *
     * @param curve The curve.
     * @param X The $X$ coordinate.
     * @param Y The $Y$ coordinate.
     * @param Z The $Z$ coordinate.
     * @param T The $T$ coordinate.
     * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
     * @return The group element in P3 representation.
     */
        return false ? new P3PreGroupElement(MathUtils.curve, x1, y1, MathUtils.getEdDSAFiniteField().ONE, t) : new P3GroupElement(MathUtils.curve, x1, y1, MathUtils.getEdDSAFiniteField().ONE, t);
    }

    /**
     * Test method for {@link BaseGroupElement#p2(Curve, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testP2() {
        @NotNull final GroupElement t = new P2GroupElement(curve, ZERO, ONE, ONE);
        assertThat(t.getCurve(), is(equalTo(curve)));
        assertThat(t.getRepr(), is(Representation.P2));
        assertThat(t.getX(), is(ZERO));
        assertThat(t.getY(), is(ONE));
        assertThat(t.getZ(), is(ONE));
        assertThat(t.getT(), is((FieldElement) null));
    }

    /**
     * Test method for {@link BaseGroupElement#p3(Curve, FieldElement, FieldElement, FieldElement, FieldElement, boolean)}.
     */
    @Test
    public void testP3() {
        /**
     * Creates a new group element in P3 representation.
     *
     * @param curve The curve.
     * @param X The $X$ coordinate.
     * @param Y The $Y$ coordinate.
     * @param Z The $Z$ coordinate.
     * @param T The $T$ coordinate.
     * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
     * @return The group element in P3 representation.
     */
        @NotNull final GroupElement t = false ? new P3PreGroupElement(curve, ZERO, ONE, ONE, ZERO) : new P3GroupElement(curve, ZERO, ONE, ONE, ZERO);
        assertThat(t.getCurve(), is(equalTo(curve)));
        assertThat(t.getRepr(), is(Representation.P3));
        assertThat(t.getX(), is(ZERO));
        assertThat(t.getY(), is(ONE));
        assertThat(t.getZ(), is(ONE));
        assertThat(t.getT(), is(ZERO));
    }

    /**
     * Test method for {@link BaseGroupElement#p1p1(Curve, FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testP1p1() {

        /**
         * Creates a new group element in P1P1 representation.
         *
         * @param curve The curve.
         * @param X The $X$ coordinate.
         * @param Y The $Y$ coordinate.
         * @param Z The $Z$ coordinate.
         * @param T The $T$ coordinate.
         * @return The group element in P1P1 representation.
         */
        @NotNull final GroupElement t = new P1pGroupElement(curve, ZERO, ONE, ONE, ONE);
        assertThat(t.getCurve(), is(equalTo(curve)));
        assertThat(t.getRepr(), is(Representation.P1P1));
        assertThat(t.getX(), is(ZERO));
        assertThat(t.getY(), is(ONE));
        assertThat(t.getZ(), is(ONE));
        assertThat(t.getT(), is(ONE));
    }

    /**
     * Test method for {@link BaseGroupElement#precomp(Curve, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testPrecomp() {
        @NotNull final GroupElement t = new PrecompGroupElement(curve, ONE, ONE, ZERO);
        assertThat(t.getCurve(), is(equalTo(curve)));
        assertThat(t.getRepr(), is(Representation.PRECOMP));
        assertThat(t.getX(), is(ONE));
        assertThat(t.getY(), is(ONE));
        assertThat(t.getZ(), is(ZERO));
        assertThat(t.getT(), is((FieldElement) null));
    }

    /**
     * Test method for {@link BaseGroupElement#cached(Curve, FieldElement, FieldElement, FieldElement, FieldElement)}.
     */
    @Test
    public void testCached() {
        @NotNull final GroupElement t = new CachedGroupElement(curve, ONE, ONE, ONE, ZERO);
        assertThat(t.getCurve(), is(equalTo(curve)));
        assertThat(t.getRepr(), is(Representation.CACHED));
        assertThat(t.getX(), is(ONE));
        assertThat(t.getY(), is(ONE));
        assertThat(t.getZ(), is(ONE));
        assertThat(t.getT(), is(ZERO));
    }

    /**
     * Test method for {@link BaseGroupElement#GroupElement(Curve, Representation, FieldElement, FieldElement, FieldElement, FieldElement, boolean)}.
     */
    @Test
    public void testGroupElementCurveRepresentationFieldElementFieldElementFieldElementFieldElement() {
        @NotNull final GroupElement t = new P3GroupElement(curve,   ZERO, ONE, ONE, ZERO );
        assertThat(t.getCurve(), is(equalTo(curve)));
        assertThat(t.getRepr(), is(Representation.P3));
        assertThat(t.getX(), is(ZERO));
        assertThat(t.getY(), is(ONE));
        assertThat(t.getZ(), is(ONE));
        assertThat(t.getT(), is(ZERO));
    }

    /**
     * Tests {@link BaseGroupElement#GroupElement(Curve, byte[])} and
     * {@link BaseGroupElement#toByteArray()} against valid public keys.
     */
    @Test
    public void testToAndFromByteArray() {
        GroupElement t;
        for (@NotNull Iterator<Ed25519TestVectors.TestTuple> iterator = Ed25519TestVectors.testCases.iterator(); iterator.hasNext(); ) {
            Ed25519TestVectors.TestTuple testCase = iterator.next();
            t = new P3GroupElement(curve, testCase.pk);
            assertThat("Test case " + testCase.caseNum + " failed",
                    t.toByteArray(), is(equalTo(testCase.pk)));
        }
    }

    /**
     * Test method for {@link BaseGroupElement#GroupElement(Curve, byte[])}.
     */
    @Test
    public void testGroupElementByteArray() {
        @NotNull final GroupElement t = new P3GroupElement(curve, BYTES_PKR);
        @NotNull final FieldElement t1 = PKR[0].multiply(PKR[1]);
        /**
     * Creates a new group element in P3 representation.
     *
     * @param curve The curve.
     * @param X The $X$ coordinate.
     * @param Y The $Y$ coordinate.
     * @param Z The $Z$ coordinate.
     * @param T The $T$ coordinate.
     * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
     * @return The group element in P3 representation.
     */
        @NotNull final GroupElement s = false ? new P3PreGroupElement(curve, PKR[0], PKR[1], ONE, t1) : new P3GroupElement(curve, PKR[0], PKR[1], ONE, t1);
        assertThat(t, is(equalTo(s)));
    }

    @Test
    public void constructorUsingByteArrayReturnsExpectedResult() {
        for (int i = 0; 100 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();
            final byte[] bytes = g.toByteArray();

            // Act:
            @NotNull final GroupElement h1 = new P3GroupElement(curve, bytes);
            @NotNull final GroupElement h2 = toGroupElement(bytes);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
        }
    }

    /**
     * Test method for {@link BaseGroupElement#toByteArray()}.
     * <p>
     * TODO 20141001 BR: why test with points which are not on the curve?
     */
    @Test
    public void testToByteArray() {
        final byte[] zerozero = new P2GroupElement(curve, ZERO, ZERO, ONE).toByteArray();
        assertThat(Integer.valueOf(zerozero.length), is(equalTo(Integer.valueOf(BYTES_ZEROZERO.length))));
        assertThat(zerozero, is(equalTo(BYTES_ZEROZERO)));

        final byte[] oneone = new P2GroupElement(curve, ONE, ONE, ONE).toByteArray();
        assertThat(Integer.valueOf(oneone.length), is(equalTo(Integer.valueOf(BYTES_ONEONE.length))));
        assertThat(oneone, is(equalTo(BYTES_ONEONE)));

        final byte[] tenzero = new P2GroupElement(curve, TEN, ZERO, ONE).toByteArray();
        assertThat(Integer.valueOf(tenzero.length), is(equalTo(Integer.valueOf(BYTES_TENZERO.length))));
        assertThat(tenzero, is(equalTo(BYTES_TENZERO)));

        final byte[] oneten = new P2GroupElement(curve, ONE, TEN, ONE).toByteArray();
        assertThat(Integer.valueOf(oneten.length), is(equalTo(Integer.valueOf(BYTES_ONETEN.length))));
        assertThat(oneten, is(equalTo(BYTES_ONETEN)));

        final byte[] pkr = new P2GroupElement(curve, PKR[0], PKR[1], ONE).toByteArray();
        assertThat(Integer.valueOf(pkr.length), is(equalTo(Integer.valueOf(BYTES_PKR.length))));
        assertThat(pkr, is(equalTo(BYTES_PKR)));
    }

     @Test
     public void toByteArrayReturnsExpectedResult() {
         for (int i = 0; 100 > i; i++) {
             // Arrange:
             final GroupElement g = MathUtils.getRandomGroupElement();

             // Act:
             final byte[] gBytes = g.toByteArray();
             @NotNull final byte[] bytes = MathUtils.toByteArray(MathUtils.toBigInteger(g.getY()));
             if (MathUtils.toBigInteger(g.getX()).mod(new BigInteger("2")).equals(BigInteger.ONE)) {
                 bytes[31] = (byte) (bytes[31] | 0x80);
             }

             // Assert:
             assertThat(Boolean.valueOf(Arrays.equals(gBytes, bytes)), IsEqual.equalTo(Boolean.TRUE));
         }
     }

    // region toX where X is the representation

    /**
     * Test method for {@link BaseGroupElement#toP2()}.
     */
    @Test
    public void testToP2() {
        final GroupElement p3zero = curve.get(Representation.P3);
        @NotNull final GroupElement t = Representation.P2.toRep(p3zero);
        assertThat(t.getRepr(), is(Representation.P2));
        assertThat(t.getX(), is(p3zero.getX()));
        assertThat(t.getY(), is(p3zero.getY()));
        assertThat(t.getZ(), is(p3zero.getZ()));
        assertThat(t.getT(), is((FieldElement) null));

        final GroupElement B = ed25519.groupElement;
        @NotNull final GroupElement t2 = Representation.P2.toRep(B);
        assertThat(t2.getRepr(), is(Representation.P2));
        assertThat(t2.getX(), is(B.getX()));
        assertThat(t2.getY(), is(B.getY()));
        assertThat(t2.getZ(), is(B.getZ()));
        assertThat(t2.getT(), is((FieldElement) null));
    }

    @Test (expected = IllegalArgumentException.class)
    public void toP2ThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        @NotNull final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.PRECOMP);

        // Assert:
        Representation.P2.toRep(g);
    }

    @Test (expected = IllegalArgumentException.class)
    public void toP2ThrowsIfGroupElementHasCachedRepresentation() {
        // Arrange:
        @NotNull final GroupElement g =  MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.CACHED);

        // Assert:
        Representation.P2.toRep(g);
    }

    @Test
    public void toP2ReturnsExpectedResultIfGroupElementHasP2Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            @NotNull final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P2);

            // Act:
            @NotNull final GroupElement h = Representation.P2.toRep(g);

            // Assert:
            assertThat(h, IsEqual.equalTo(g));
            assertThat(h.getRepresentation(), IsEqual.equalTo(Representation.P2));
            assertThat(h.getX(), IsEqual.equalTo(g.getX()));
            assertThat(h.getY(), IsEqual.equalTo(g.getY()));
            assertThat(h.getZ(), IsEqual.equalTo(g.getZ()));
            assertThat(h.getT(), IsEqual.equalTo(null));
        }
    }

    @Test
    public void toP2ReturnsExpectedResultIfGroupElementHasP3Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Act:
            @NotNull final GroupElement h1 = Representation.P2.toRep(g);
            @NotNull final GroupElement h2 = MathUtils.toRepresentation(g, Representation.P2);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
            assertThat(h1.getRepresentation(), IsEqual.equalTo(Representation.P2));
            assertThat(h1.getX(), IsEqual.equalTo(g.getX()));
            assertThat(h1.getY(), IsEqual.equalTo(g.getY()));
            assertThat(h1.getZ(), IsEqual.equalTo(g.getZ()));
            assertThat(h1.getT(), IsEqual.equalTo(null));
        }
    }

    @Test
    public void toP2ReturnsExpectedResultIfGroupElementHasP1P1Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            @NotNull final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P1P1);

            // Act:
            @NotNull final GroupElement h1 = Representation.P2.toRep(g);
            @NotNull final GroupElement h2 = MathUtils.toRepresentation(g, Representation.P2);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
            assertThat(h1.getRepresentation(), IsEqual.equalTo(Representation.P2));
            assertThat(h1.getX(), IsEqual.equalTo(g.getX().multiply(g.getT())));
            assertThat(h1.getY(), IsEqual.equalTo(g.getY().multiply(g.getZ())));
            assertThat(h1.getZ(), IsEqual.equalTo(g.getZ().multiply(g.getT())));
            assertThat(h1.getT(), IsEqual.equalTo(null));
        }
    }

    @Test (expected = IllegalArgumentException.class)
    public void toP3ThrowsIfGroupElementHasP2Representation() {
        // Arrange:
        @NotNull final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P2);

        // Assert:
        Representation.P3.toRep(g);
    }

    @Test (expected = IllegalArgumentException.class)
    public void toP3ThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        @NotNull final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.PRECOMP);

        // Assert:
        Representation.P3.toRep(g);
    }

    @Test (expected = IllegalArgumentException.class)
    public void toP3ThrowsIfGroupElementHasCachedRepresentation() {
        // Arrange:
        @NotNull final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.CACHED);

        // Assert:
        Representation.P3.toRep(g);
    }

    @Test
    public void toP3ReturnsExpectedResultIfGroupElementHasP1P1Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            @NotNull final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P1P1);

            // Act:
            @NotNull final GroupElement h1 = Representation.P3.toRep(g);
            @NotNull final GroupElement h2 = MathUtils.toRepresentation(g, Representation.P3);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
            assertThat(h1.getRepresentation(), IsEqual.equalTo(Representation.P3));
            assertThat(h1.getX(), IsEqual.equalTo(g.getX().multiply(g.getT())));
            assertThat(h1.getY(), IsEqual.equalTo(g.getY().multiply(g.getZ())));
            assertThat(h1.getZ(), IsEqual.equalTo(g.getZ().multiply(g.getT())));
            assertThat(h1.getT(), IsEqual.equalTo(g.getX().multiply(g.getY())));
        }
    }

    @Test
    public void toP3ReturnsExpectedResultIfGroupElementHasP3Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Act:
            @NotNull final GroupElement h = Representation.P3.toRep(g);

            // Assert:
            assertThat(h, IsEqual.equalTo(g));
            assertThat(h.getRepresentation(), IsEqual.equalTo(Representation.P3));
            assertThat(h, IsEqual.equalTo(g));
            assertThat(h.getX(), IsEqual.equalTo(g.getX()));
            assertThat(h.getY(), IsEqual.equalTo(g.getY()));
            assertThat(h.getZ(), IsEqual.equalTo(g.getZ()));
            assertThat(h.getT(), IsEqual.equalTo(g.getT()));
        }
    }

    @Test (expected = IllegalArgumentException.class)
    public void toCachedThrowsIfGroupElementHasP2Representation() {
        // Arrange:
        @NotNull final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P2);

        // Assert:
        Representation.CACHED.toRep(g);
    }

    @Test (expected = IllegalArgumentException.class)
    public void toCachedThrowsIfGroupElementHasPrecompRepresentation() {
        // Arrange:
        @NotNull final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.PRECOMP);

        // Assert:
        Representation.CACHED.toRep(g);
    }

    @Test (expected = IllegalArgumentException.class)
    public void toCachedThrowsIfGroupElementHasP1P1Representation() {
        // Arrange:
        @NotNull final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.P1P1);

        // Assert:
        Representation.CACHED.toRep(g);
    }

    @Test
    public void toCachedReturnsExpectedResultIfGroupElementHasCachedRepresentation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            @NotNull final GroupElement g = MathUtils.toRepresentation(MathUtils.getRandomGroupElement(), Representation.CACHED);

            // Act:
            @NotNull final GroupElement h = Representation.CACHED.toRep(g);

            // Assert:
            assertThat(h, IsEqual.equalTo(g));
            assertThat(h.getRepresentation(), IsEqual.equalTo(Representation.CACHED));
            assertThat(h, IsEqual.equalTo(g));
            assertThat(h.getX(), IsEqual.equalTo(g.getX()));
            assertThat(h.getY(), IsEqual.equalTo(g.getY()));
            assertThat(h.getZ(), IsEqual.equalTo(g.getZ()));
            assertThat(h.getT(), IsEqual.equalTo(g.getT()));
        }
    }

    @Test
    public void toCachedReturnsExpectedResultIfGroupElementHasP3Representation() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Act:
            @NotNull final GroupElement h1 = Representation.CACHED.toRep(g);
            @NotNull final GroupElement h2 = MathUtils.toRepresentation(g, Representation.CACHED);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
            assertThat(h1.getRepresentation(), IsEqual.equalTo(Representation.CACHED));
            assertThat(h1, IsEqual.equalTo(g));
            assertThat(h1.getX(), IsEqual.equalTo(g.getY().add(g.getX())));
            assertThat(h1.getY(), IsEqual.equalTo(g.getY().subtract(g.getX())));
            assertThat(h1.getZ(), IsEqual.equalTo(g.getZ()));
            assertThat(h1.getT(), IsEqual.equalTo(g.getT().multiply(curve.getFieldElementD2())));
        }
    }

    // endregion

    /**
     * Test method for precomputation.
     */
    @Test
    public void testPrecompute() {
        final GroupElement B = ed25519.groupElement;
        assertThat(B.getPrecmp(), is(equalTo(PrecomputationTestVectors.testPrecmp)));
        assertThat(B.getDblPrecmp(), is(equalTo(PrecomputationTestVectors.testDblPrecmp)));
    }

    @Test
    public void precomputedTableContainsExpectedGroupElements() {
        // Arrange:
        GroupElement g = ed25519.groupElement;

        // Act + Assert:
        for (int i = 0; 32 > i; i++) {
            GroupElement h = g;
            for (int j = 0; 8 > j; j++) {
                assertThat(MathUtils.toRepresentation(h, Representation.PRECOMP), IsEqual.equalTo(ed25519.groupElement.getPrecmp()[i][j]));
                h = MathUtils.addGroupElements(h, g);
            }
            for (int k = 0; 8 > k; k++) {
                g = MathUtils.addGroupElements(g, g);
            }
        }
    }

    @Test
    public void dblPrecomputedTableContainsExpectedGroupElements() {
        // Arrange:
        GroupElement g = ed25519.groupElement;
        @NotNull final GroupElement h = MathUtils.addGroupElements(g, g);

        // Act + Assert:
        for (int i = 0; 8 > i; i++) {
            assertThat(MathUtils.toRepresentation(g, Representation.PRECOMP), IsEqual.equalTo(ed25519.groupElement.getDblPrecmp()[i]));
            g = MathUtils.addGroupElements(g, h);
        }
    }

    /**
     * Test method for {@link BaseGroupElement#dbl()}.
     */
    @Test
    public void testDbl() {
        final GroupElement B = ed25519.groupElement;
        // 2 * B = B + B
        assertThat(B.dbl(), is(equalTo(B.add(Representation.CACHED.toRep(B)))));
    }

    @Test
    public void dblReturnsExpectedResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h1 = g.dbl();
            @NotNull final GroupElement h2 = MathUtils.doubleGroupElement(g);

            // Assert:
            assertThat(h2, IsEqual.equalTo(h1));
        }
    }

    @Test
    public void addingNeutralGroupElementDoesNotChangeGroupElement() {
        /**
     * Creates a new group element in P3 representation.
     *
     * @param curve The curve.
     * @param X The $X$ coordinate.
     * @param Y The $Y$ coordinate.
     * @param Z The $Z$ coordinate.
     * @param T The $T$ coordinate.
     * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
     * @return The group element in P3 representation.
     */
        @NotNull final GroupElement neutral = false ? new P3PreGroupElement(curve, curve.getEdDSAFiniteField().ZERO, curve.getEdDSAFiniteField().ONE, curve.getEdDSAFiniteField().ONE, curve.getEdDSAFiniteField().ZERO) : new P3GroupElement(curve, curve.getEdDSAFiniteField().ZERO, curve.getEdDSAFiniteField().ONE, curve.getEdDSAFiniteField().ONE, curve.getEdDSAFiniteField().ZERO);
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h1 = g.add(Representation.CACHED.toRep(neutral));
            final GroupElement h2 = neutral.add(Representation.CACHED.toRep(g));

            // Assert:
            assertThat(g, IsEqual.equalTo(h1));
            assertThat(g, IsEqual.equalTo(h2));
        }
    }

    @Test
    public void addReturnsExpectedResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            final GroupElement g1 = MathUtils.getRandomGroupElement();
            final GroupElement g2 = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h1 = g1.add(Representation.CACHED.toRep(g2));
            @NotNull final GroupElement h2 = MathUtils.addGroupElements(g1, g2);

            // Assert:
            assertThat(h2, IsEqual.equalTo(h1));
        }
    }

    @Test
    public void subReturnsExpectedResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            final GroupElement g1 = MathUtils.getRandomGroupElement();
            final GroupElement g2 = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h1 = g1.sub(Representation.CACHED.toRep(g2));
            @NotNull final GroupElement h2 = MathUtils.addGroupElements(g1, negateGroupElement(g2));

            // Assert:
            assertThat(h2, IsEqual.equalTo(h1));
        }
    }

    // region hashCode / equals
    /**
     * Test method for {@link BaseGroupElement#equals(java.lang.Object)}.
     */
    @Test
    public void testEqualsObject() {
        assertThat(new P2GroupElement(curve, ZERO, ONE, ONE),
                is(equalTo(P2_ZERO)));
    }

    @Test
    public void equalsOnlyReturnsTrueForEquivalentObjects() {
        // Arrange:
        final GroupElement g1 = MathUtils.getRandomGroupElement();
        @NotNull final GroupElement g2 = MathUtils.toRepresentation(g1, Representation.P2);
        @NotNull final GroupElement g3 = MathUtils.toRepresentation(g1, Representation.CACHED);
        @NotNull final GroupElement g4 = MathUtils.toRepresentation(g1, Representation.P1P1);
        final GroupElement g5 = MathUtils.getRandomGroupElement();

        // Assert
        assertThat(g2, IsEqual.equalTo(g1));
        assertThat(g3, IsEqual.equalTo(g1));
        assertThat(g1, IsEqual.equalTo(g4));
        assertThat(g1, IsNot.not(IsEqual.equalTo(g5)));
        assertThat(g2, IsNot.not(IsEqual.equalTo(g5)));
        assertThat(g3, IsNot.not(IsEqual.equalTo(g5)));
        assertThat(g5, IsNot.not(IsEqual.equalTo(g4)));
    }

    @Test
    public void hashCodesAreEqualForEquivalentObjects() {
        // Arrange:
        final GroupElement g1 = MathUtils.getRandomGroupElement();
        @NotNull final GroupElement g2 = MathUtils.toRepresentation(g1, Representation.P2);
        @NotNull final GroupElement g3 = MathUtils.toRepresentation(g1, Representation.P1P1);
        final GroupElement g4 = MathUtils.getRandomGroupElement();

        // Assert
        assertThat(Integer.valueOf(g2.hashCode()), IsEqual.equalTo(Integer.valueOf(g1.hashCode())));
        assertThat(Integer.valueOf(g3.hashCode()), IsEqual.equalTo(Integer.valueOf(g1.hashCode())));
        assertThat(Integer.valueOf(g1.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(g4.hashCode()))));
        assertThat(Integer.valueOf(g2.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(g4.hashCode()))));
        assertThat(Integer.valueOf(g3.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(g4.hashCode()))));
    }

    // endregion

    private static final byte[] BYTES_ZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] BYTES_ONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] BYTES_42 = Utils.hexToBytes("2A00000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] BYTES_1234567890 = Utils.hexToBytes("D202964900000000000000000000000000000000000000000000000000000000");

    private static final byte[] RADIX16_ZERO = Utils.hexToBytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] RADIX16_ONE = Utils.hexToBytes("01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] RADIX16_42 = Utils.hexToBytes("FA030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    /**
     * Test method for {@link BaseGroupElement#toRadix16(byte[])}.
     */
    @Test
    public void testToRadix16() {
        assertThat(GroupElement.toRadix16(BYTES_ZERO), is(RADIX16_ZERO));
        assertThat(GroupElement.toRadix16(BYTES_ONE), is(RADIX16_ONE));
        assertThat(GroupElement.toRadix16(BYTES_42), is(RADIX16_42));

        @NotNull final byte[] from1234567890 = GroupElement.toRadix16(BYTES_1234567890);
        int total = 0;
        for (int i = 0; i < from1234567890.length; i++) {
            assertThat(Byte.valueOf(from1234567890[i]), is(greaterThanOrEqualTo(Byte.valueOf((byte) -8))));
            assertThat(Byte.valueOf(from1234567890[i]), is(lessThanOrEqualTo(Byte.valueOf((byte) 8))));
            total = (int) ((double) total + from1234567890[i] * StrictMath.pow(16.0, (double) i));
        }
        assertThat(Integer.valueOf(total), is(Integer.valueOf(1234567890)));

        @NotNull final byte[] pkrR16 = GroupElement.toRadix16(BYTES_PKR);
        final int bound = pkrR16.length;
        for (int i = 0; i < bound; i++) {
            assertThat(Byte.valueOf(pkrR16[i]), is(greaterThanOrEqualTo(Byte.valueOf((byte) -8))));
            assertThat(Byte.valueOf(pkrR16[i]), is(lessThanOrEqualTo(Byte.valueOf((byte) 8))));
        }
    }

    /**
     * Test method for {@link BaseGroupElement#cmov(GroupElement, int)}.
     */
    @Test
    public void testCmov() {
        final GroupElement a = curve.get(Representation.PRECOMP);
        @NotNull final GroupElement b = new PrecompGroupElement(curve, TWO, ZERO, TEN);
        assertThat(a.cmov(b, 0), is(equalTo(a)));
        assertThat(a.cmov(b, 1), is(equalTo(b)));
    }

    /**
     * Test method for {@link BaseGroupElement#select(int, int)}.
     */
    @Test
    public void testSelect() {
        final GroupElement B = ed25519.groupElement;
        for (int i = 0; 32 > i; i++) {
            // 16^i 0 B
            assertThat(i + ",0", B.select(i, 0),
                    is(equalTo(new PrecompGroupElement(curve, ONE, ONE, ZERO))));
            for (int j = 1; 8 > j; j++) {
                // 16^i r_i B
                GroupElement t = B.select(i, j);
                assertThat(i + "," + j,
                        t, is(equalTo(B.getPrecmp()[i][j-1])));
                // -16^i r_i B
                final GroupElement t3 = B.select(i, -j);
                @NotNull final GroupElement neg = new PrecompGroupElement(curve, B.getPrecmp()[i][j - 1].getY(), B.getPrecmp()[i][j - 1].getX(), B.getPrecmp()[i][j - 1].getZ().negate());
                assertThat(i + "," + -j,
                        t3, is(equalTo(neg)));
            }
        }
    }

    // region scalar multiplication
    /**
     * Test method for {@link BaseGroupElement#scalarMultiply(byte[])}.
     * Test values generated with Python Ed25519 implementation.
     */
    @Test
    public void testScalarMultiplyByteArray() {
        // Little-endian
        @NotNull final byte[] zero = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
        @NotNull final byte[] one = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
        @NotNull final byte[] two = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000");
        @NotNull final byte[] a = Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c");
        @NotNull final GroupElement A = new P3GroupElement(curve, Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66")){};

        assertThat("scalarMultiply(0) failed",
                ed25519.groupElement.scalarMultiply(zero), is(equalTo(curve.get(Representation.P3))));
        assertThat("scalarMultiply(1) failed",
                ed25519.groupElement.scalarMultiply(one), is(equalTo(ed25519.groupElement)));
        assertThat("scalarMultiply(2) failed",
                ed25519.groupElement.scalarMultiply(two), is(equalTo(ed25519.groupElement.dbl())));

        assertThat("scalarMultiply(a) failed",
                ed25519.groupElement.scalarMultiply(a), is(equalTo(A)));
    }

    @Test
    public void scalarMultiplyBasePointWithZeroReturnsNeutralElement() {
        // Arrange:
        final GroupElement basePoint = ed25519.groupElement;

        // Act:
        final GroupElement g = basePoint.scalarMultiply(curve.getEdDSAFiniteField().ZERO.toByteArray());

        // Assert:
        assertThat(curve.get(Representation.P3), IsEqual.equalTo(g));
    }

    @Test
    public void scalarMultiplyBasePointWithOneReturnsBasePoint() {
        // Arrange:
        final GroupElement basePoint = ed25519.groupElement;

        // Act:
        final GroupElement g = basePoint.scalarMultiply(curve.getEdDSAFiniteField().ONE.toByteArray());

        // Assert:
        assertThat(basePoint, IsEqual.equalTo(g));
    }

    // This test is slow (~6s) due to math utils using an inferior algorithm to calculate the result.
    @Test
    public void scalarMultiplyBasePointReturnsExpectedResult() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement basePoint = ed25519.groupElement;
            @NotNull final FieldElement f = MathUtils.getRandomFieldElement();

            // Act:
            final GroupElement g = basePoint.scalarMultiply(f.toByteArray());
            final GroupElement h = MathUtils.scalarMultiplyGroupElement(basePoint, f);

            // Assert:
            assertThat(g, IsEqual.equalTo(h));
        }
    }

    @Test
    public void testDoubleScalarMultiplyVariableTime() {
        // Little-endian
        @NotNull final byte[] zero = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
        @NotNull final byte[] one = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
        @NotNull final byte[] two = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000");
        @NotNull final byte[] a = Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c");
        @NotNull final GroupElement A = new P3GroupElement(curve, Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66"));
        final GroupElement B = ed25519.groupElement;
        final GroupElement geZero = curve.get(Representation.P3PrecomputedDouble);

        // 0 * GE(0) + 0 * GE(0) = GE(0)
        assertThat(geZero.doubleScalarMultiplyVariableTime(geZero, zero, zero),
                is(equalTo(geZero)));
        // 0 * GE(0) + 0 * B = GE(0)
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, zero, zero),
                is(equalTo(geZero)));
        // 1 * GE(0) + 0 * B = GE(0)
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, one, zero),
                is(equalTo(geZero)));
        // 1 * GE(0) + 1 * B = B
        assertThat(B.doubleScalarMultiplyVariableTime(geZero, one, one),
                is(equalTo(B)));
        // 1 * B + 1 * B = 2 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, one, one),
                is(equalTo(B.dbl())));
        // 1 * B + 2 * B = 3 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, one, two),
                is(equalTo(Representation.P3.toRep(B.dbl()).add(Representation.CACHED.toRep(B)))));
        // 2 * B + 2 * B = 4 * B
        assertThat(B.doubleScalarMultiplyVariableTime(B, two, two),
                is(equalTo(Representation.P3.toRep(B.dbl()).dbl())));

        // 0 * B + a * B = A
        assertThat(B.doubleScalarMultiplyVariableTime(B, zero, a),
                is(equalTo(A)));
        // a * B + 0 * B = A
        assertThat(B.doubleScalarMultiplyVariableTime(B, a, zero),
                is(equalTo(A)));
        // a * B + a * B = 2 * A
        assertThat(B.doubleScalarMultiplyVariableTime(B, a, a),
                is(equalTo(A.dbl())));
    }

    // This test is slow (~6s) due to math utils using an inferior algorithm to calculate the result.
    @Test
    public void doubleScalarMultiplyVariableTimeReturnsExpectedResult() {
        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement basePoint = ed25519.groupElement;
            @NotNull final byte[] bytes = new byte[32];
            GroupElement ret;
            while (true) {
                try {
                    MathUtils.random.nextBytes(bytes);
                    ret = new P3PreGroupElement(  MathUtils.curve, bytes );
                    break;
                } catch (@NotNull final Throwable e) {
                    // Will fail in about 87.5%, so try again.
                }
            }
            final GroupElement g = ret;
            @NotNull final FieldElement f1 = MathUtils.getRandomFieldElement();
            @NotNull final FieldElement f2 = MathUtils.getRandomFieldElement();

            // Act:
            final GroupElement h1 = basePoint.doubleScalarMultiplyVariableTime(g, f2.toByteArray(), f1.toByteArray());
            @NotNull final GroupElement h2 = doubleScalarMultiplyGroupElements(basePoint, f1, g, f2);

            // Assert:
            assertThat(h1, IsEqual.equalTo(h2));
        }
    }

    // endregion

    /**
     * Test method for {@link BaseGroupElement#isOnCurve(Curve)}.
     */
    @Test
    public void testIsOnCurve() {
        assertThat(Boolean.valueOf(P2_ZERO.isOnCurve(curve)),
                is(Boolean.TRUE));
        assertThat(Boolean.valueOf(new P2GroupElement(curve, ZERO, ZERO, ONE).isOnCurve(curve)),
                is(Boolean.FALSE));
        assertThat(Boolean.valueOf(new P2GroupElement(curve, ONE, ONE, ONE).isOnCurve(curve)),
                is(Boolean.FALSE));
        assertThat(Boolean.valueOf(new P2GroupElement(curve, TEN, ZERO, ONE).isOnCurve(curve)),
                is(Boolean.FALSE));
        assertThat(Boolean.valueOf(new P2GroupElement(curve, ONE, TEN, ONE).isOnCurve(curve)),
                is(Boolean.FALSE));
        assertThat(Boolean.valueOf(new P2GroupElement(curve, PKR[0], PKR[1], ONE).isOnCurve(curve)),
                is(Boolean.TRUE));
    }

    @Test
    public void isOnCurveReturnsTrueForPointsOnTheCurve() {
        for (int i = 0; 100 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Assert:
            assertThat(Boolean.valueOf(g.isOnCurve()), IsEqual.equalTo(Boolean.TRUE));
        }
    }

    @Test
    public void isOnCurveReturnsFalseForPointsNotOnTheCurve() {
        for (int i = 0; 100 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();
            @NotNull final GroupElement h = new P2GroupElement(curve, g.getX(), g.getY(), g.getZ().multiply(curve.getEdDSAFiniteField().TWO));

            // Assert (can only fail for 5*Z^2=1):
            assertThat(Boolean.valueOf(h.isOnCurve()), IsEqual.equalTo(Boolean.FALSE));
        }
    }
}
