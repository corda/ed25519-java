/**
 * EdDSA-Java by str4d
 * <p>
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 * <p>
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 */
package net.i2p.crypto.eddsa.math;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import org.hamcrest.core.IsEqual;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Utility class to help with calculations.
 */
public class MathUtils {
    public static final int[] exponents = {0, 26, 26 + 25, 2 * 26 + 25, 2 * 26 + 2 * 25, 3 * 26 + 2 * 25, 3 * 26 + 3 * 25, 4 * 26 + 3 * 25, 4 * 26 + 4 * 25, 5 * 26 + 4 * 25};
    public static final SecureRandom random = new SecureRandom();
    public static final BigInteger d = new BigInteger("-121665").multiply(new BigInteger("121666").modInverse(getQ()));
    public static final BigInteger groupOrder = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
    public static final Curve curve = ed25519.curve;

    /**
     * Gets q = 2^255 - 19 as BigInteger.
     */
    public static BigInteger getQ() {
        return new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
    }

    /**
     * Gets the underlying finite field with q=2^255 - 19 elements.
     *
     * @return The finite field.
     */
    public static EdDSAFiniteField getEdDSAFiniteField() {
        return new EdDSAFiniteField(
                256, // b
                Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
                new Ed25519LittleEndianEncoding().getEmptyEncoding());
    }

    // region field element

    /**
     * Converts a 2^8 bit representation to a BigInteger.
     * <p>
     * Value: bytes[0] + 2^8 * bytes[1] + ...
     *
     * @param bytes The 2^8 bit representation.
     * @return The BigInteger.
     */
    public static BigInteger toBigInteger(final byte[] bytes) {
        BigInteger b = BigInteger.ZERO;
        for (int i = 0; i < bytes.length; i++) {
            b = b.add(BigInteger.ONE.multiply(BigInteger.valueOf((long) (bytes[i] & 0xff))).shiftLeft(i * 8));
        }

        return b;
    }

    /**
     * Converts a field element to a BigInteger.
     *
     * @param f The field element.
     * @return The BigInteger.
     */
    public static BigInteger toBigInteger(final FieldElement f) {
        return toBigInteger(f.toByteArray());
    }

    /**
     * Converts a BigInteger to a field element.
     *
     * @param b The BigInteger.
     * @return The field element.
     */
    @NotNull
    public static FieldElement toFieldElement(@NotNull final BigInteger b) {
        return getEdDSAFiniteField().getEncoding().decode(toByteArray(b));
    }

    /**
     * Converts a BigInteger to a little endian 32 byte representation.
     *
     * @param b The BigInteger.
     * @return The 32 byte representation.
     */
    @NotNull
    public static byte[] toByteArray(final BigInteger b) {
        if (0 <= b.compareTo(BigInteger.ONE.shiftLeft(256))) {
            throw new RuntimeException("only numbers < 2^256 are allowed");
        }
        @NotNull final byte[] bytes = new byte[32];
        final byte[] original = b.toByteArray();

        // Although b < 2^256, original can have length > 32 with some bytes set to 0.
        final int offset = 32 < original.length ? original.length - 32 : 0;
        for (int i = 0; i < original.length - offset; i++) {
            bytes[original.length - i - offset - 1] = original[i + offset];
        }

        return bytes;
    }

    /**
     * Gets a random field element where |t[i]| <= 2^24 for 0 <= i <= 9.
     *
     * @return The field element.
     */
    public static FieldElement getRandomFieldElement() {
        @NotNull final int[] t = new int[10];
        for (int j = 0; 10 > j; j++) {
            t[j] = random.nextInt(1 << 25) - (1 << 24);
        }
        return new Ed25519FieldElement(getEdDSAFiniteField(), t);
    }

    // endregion

    // region group element

    /**
     * Gets a random group element in P3 representation.
     *
     * @return The group element.
     */
    public static GroupElement getRandomGroupElement() {
        return getRandomGroupElement(false);
    }

    /**
     * Gets a random group element in P3 representation, with precmp and dblPrecmp populated.
     *
     * @return The group element.
     */
    public static GroupElement getRandomGroupElement(final boolean precompute) {
        @NotNull final byte[] bytes = new byte[32];
        GroupElement ret;
        while (true) {
            try {
                random.nextBytes(bytes);
                ret = new BaseGroupElement(curve, bytes, precompute);
                break;
            } catch (@NotNull final Throwable e) {
                // Will fail in about 87.5%, so try again.
            }
        }
        return ret;
    }

    /**
     * Converts a group element from one representation to another.
     * This method is a helper used to test various methods in GroupElement.
     *
     * @param g    The group element.
     * @param repr The desired representation.
     * @return The same group element in the new representation.
     */
    public static GroupElement toRepresentation(final GroupElement g, @NotNull final Representation repr) {
        final BigInteger x;
        final BigInteger y;
        final BigInteger gX = toBigInteger(g.getX().toByteArray());
        final BigInteger gY = toBigInteger(g.getY().toByteArray());
        final BigInteger gZ = toBigInteger(g.getZ().toByteArray());
        @Nullable final BigInteger gT = null == g.getT() ? null : toBigInteger(g.getT().toByteArray());

        // Switch to affine coordinates.
        switch (g.getRepresentation()) {
            case P2:
            case P3:
                x = gX.multiply(gZ.modInverse(getQ())).mod(getQ());
                y = gY.multiply(gZ.modInverse(getQ())).mod(getQ());
                break;
            case P1P1:
                x = gX.multiply(gZ.modInverse(getQ())).mod(getQ());
                y = gY.multiply(gT.modInverse(getQ())).mod(getQ());
                break;
            case CACHED:
                x = gX.subtract(gY).multiply(gZ.multiply(new BigInteger("2")).modInverse(getQ())).mod(getQ());
                y = gX.add(gY).multiply(gZ.multiply(new BigInteger("2")).modInverse(getQ())).mod(getQ());
                break;
            case PRECOMP:
                x = gX.subtract(gY).multiply(new BigInteger("2").modInverse(getQ())).mod(getQ());
                y = gX.add(gY).multiply(new BigInteger("2").modInverse(getQ())).mod(getQ());
                break;
            default:
                throw new UnsupportedOperationException();
        }

        // Now back to the desired representation.
        switch (repr) {
            case P2:
                return new P2GroupElement(curve, toFieldElement(x), toFieldElement(y), getEdDSAFiniteField().ONE);
            case P3:
                @NotNull final FieldElement x1 = toFieldElement(x);
                @NotNull final FieldElement y1 = toFieldElement(y);
                @NotNull final FieldElement t = toFieldElement(x.multiply(y).mod(getQ()));
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
                return false ? new P3PreGroupElement(curve, x1, y1, getEdDSAFiniteField().ONE, t) : new P3GroupElement(curve, x1, y1, getEdDSAFiniteField().ONE, t);
            case P1P1:

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
                return new P1pGroupElement(curve, toFieldElement(x), toFieldElement(y), getEdDSAFiniteField().ONE, getEdDSAFiniteField().ONE);
            case CACHED:
                return new CachedGroupElement(curve, toFieldElement(y.add(x).mod(getQ())), toFieldElement(y.subtract(x).mod(getQ())), getEdDSAFiniteField().ONE, toFieldElement(d.multiply(new BigInteger("2")).multiply(x).multiply(y).mod(getQ())));
            case PRECOMP:
                return
                        /**
                         * Creates a new group element in PRECOMP representation.
                         *
                         * @param curve The curve.
                         * @param ypx The $y + x$ value.
                         * @param ymx The $y - x$ value.
                         * @param xy2d The $2 * d * x * y$ value.
                         * @return The group element in PRECOMP representation.
                         */new PrecompGroupElement(curve, toFieldElement(y.add(x).mod(getQ())), toFieldElement(y.subtract(x).mod(getQ())), toFieldElement(d.multiply(new BigInteger("2")).multiply(x).multiply(y).mod(getQ())));
            default:
                throw new UnsupportedOperationException();
        }
    }

    /**
     * Adds two group elements and returns the result in P3 representation.
     * It uses BigInteger arithmetic and the affine representation.
     * This method is a helper used to test the projective group addition formulas in GroupElement.
     *
     * @param g1 The first group element.
     * @param g2 The second group element.
     * @return The result of the addition.
     */
    public static GroupElement addGroupElements(final GroupElement g1, @NotNull final GroupElement g2) {
        // Relying on a special representation of the group elements.
        if ((Representation.P2 != g1.getRepresentation() && Representation.P3 != g1.getRepresentation()) ||
                (Representation.P2 != g2.getRepresentation() && Representation.P3 != g2.getRepresentation())) {
            throw new IllegalArgumentException("g1 and g2 must have representation P2 or P3");
        }

        // Projective coordinates
        final BigInteger g1X = toBigInteger(g1.getX().toByteArray());
        final BigInteger g1Y = toBigInteger(g1.getY().toByteArray());
        final BigInteger g1Z = toBigInteger(g1.getZ().toByteArray());
        final BigInteger g2X = toBigInteger(g2.getX().toByteArray());
        final BigInteger g2Y = toBigInteger(g2.getY().toByteArray());
        final BigInteger g2Z = toBigInteger(g2.getZ().toByteArray());

        // Affine coordinates
        final BigInteger g1x = g1X.multiply(g1Z.modInverse(getQ())).mod(getQ());
        final BigInteger g1y = g1Y.multiply(g1Z.modInverse(getQ())).mod(getQ());
        final BigInteger g2x = g2X.multiply(g2Z.modInverse(getQ())).mod(getQ());
        final BigInteger g2y = g2Y.multiply(g2Z.modInverse(getQ())).mod(getQ());

        // Addition formula for affine coordinates. The formula is complete in our case.
        //
        // (x3, y3) = (x1, y1) + (x2, y2) where
        //
        // x3 = (x1 * y2 + x2 * y1) / (1 + d * x1 * x2 * y1 * y2) and
        // y3 = (x1 * x2 + y1 * y2) / (1 - d * x1 * x2 * y1 * y2) and
        // d = -121665/121666
        final BigInteger dx1x2y1y2 = d.multiply(g1x).multiply(g2x).multiply(g1y).multiply(g2y).mod(getQ());
        final BigInteger x3 = g1x.multiply(g2y).add(g2x.multiply(g1y))
                .multiply(BigInteger.ONE.add(dx1x2y1y2).modInverse(getQ())).mod(getQ());
        final BigInteger y3 = g1x.multiply(g2x).add(g1y.multiply(g2y))
                .multiply(BigInteger.ONE.subtract(dx1x2y1y2).modInverse(getQ())).mod(getQ());
        final BigInteger t3 = x3.multiply(y3).mod(getQ());

        final Curve curve1 = g1.getCurve();
        @NotNull final FieldElement x = toFieldElement(x3);
        @NotNull final FieldElement y = toFieldElement(y3);
        @NotNull final FieldElement t = toFieldElement(t3);
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
        return false ? new P3PreGroupElement(curve1, x, y, getEdDSAFiniteField().ONE, t) : new P3GroupElement(curve1, x, y, getEdDSAFiniteField().ONE, t);
    }

    /**
     * Doubles a group element and returns the result in P3 representation.
     * It uses BigInteger arithmetic and the affine representation.
     * This method is a helper used to test the projective group doubling formula in GroupElement.
     *
     * @param g The group element.
     * @return g+g.
     */
    public static GroupElement doubleGroupElement(@NotNull final GroupElement g) {
        return addGroupElements(g, g);
    }

    /**
     * Scalar multiply the group element by the field element.
     *
     * @param g The group element.
     * @param f The field element.
     * @return The resulting group element.
     */
    public static GroupElement scalarMultiplyGroupElement(@NotNull final GroupElement g, final FieldElement f) {
        final byte[] bytes = f.toByteArray();
        GroupElement h = curve.get(Representation.P3);
        for (int i = 254; 0 <= i; i--) {
            h = doubleGroupElement(h);
            if (1 == Utils.bit(bytes, i)) {
                h = addGroupElements(h, g);
            }
        }

        return h;
    }

    // Start TODO BR: Remove when finished!
    @Test
    public void mathUtilsWorkAsExpected() {
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
            final GroupElement g = getRandomGroupElement();

            // Act:
            @NotNull final GroupElement h1 = addGroupElements(g, neutral);
            @NotNull final GroupElement h2 = addGroupElements(neutral, g);

            // Assert:
            Assert.assertThat(g, IsEqual.equalTo(h1));
            Assert.assertThat(g, IsEqual.equalTo(h2));
        }

        for (int i = 0; 1000 > i; i++) {
            final GroupElement ga1 = getRandomGroupElement();

            // P3 -> P2.
            @NotNull final GroupElement h = toRepresentation(ga1, Representation.P2);
            Assert.assertThat(h, IsEqual.equalTo(ga1));
            // P3 -> P1P1.
            @NotNull final GroupElement g2 = toRepresentation(ga1, Representation.P1P1);
            Assert.assertThat(ga1, IsEqual.equalTo(g2));

            // P3 -> CACHED.
            @NotNull final GroupElement g3 = toRepresentation(ga1, Representation.CACHED);
            Assert.assertThat(g3, IsEqual.equalTo(ga1));
            // P3 -> P2 -> P3.
            @NotNull final GroupElement gb1 = toRepresentation(ga1, Representation.P2);
            @NotNull final GroupElement g4 = toRepresentation(gb1, Representation.P3);
            Assert.assertThat(gb1, IsEqual.equalTo(g4));
            // P3 -> P2 -> P1P1.
            @NotNull final GroupElement g = toRepresentation(gb1, Representation.P2);
            @NotNull final GroupElement g5 = toRepresentation(g, Representation.P1P1);
            Assert.assertThat(g, IsEqual.equalTo(g5));


        }

        for (int i = 0; 10 > i; i++) {
            // Arrange:
            final GroupElement g = MathUtils.getRandomGroupElement();

            // Act:
            final GroupElement h = MathUtils.scalarMultiplyGroupElement(g, curve.getEdDSAFiniteField().ZERO);

            // Assert:
            Assert.assertThat(curve.get(Representation.P3), IsEqual.equalTo(h));
        }
    }
    // End TODO BR: Remove when finished!
}
