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
import org.hamcrest.core.IsEqual;
import org.junit.*;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Tests rely on the BigInteger class.
 */
public class Ed25519LittleEndianEncodingTest {

    public static final SecureRandom random = new SecureRandom();

    /**
     * Converts a 2^25.5 bit representation to a BigInteger.
     * <p>
     * Value: 2^exponents[0] * t[0] + 2^exponents[1] * t[1] + ... + 2^exponents[9] * t[9]
     *
     * @param t The 2^25.5 bit representation.
     * @return The BigInteger.
     */
    public static BigInteger toBigInteger(final int[] t) {
        BigInteger b = BigInteger.ZERO;
        for (int i = 0; 10 > i; i++) {
            b = b.add(BigInteger.ONE.multiply(BigInteger.valueOf(t[i])).shiftLeft(MathUtils.exponents[i]));
        }

        return b;
    }

    @Test
    public void encodeReturnsCorrectByteArrayForSimpleFieldElements() {
        // Arrange:
        final int[] t1 = new int[10];
        final int[] t2 = new int[10];
        t2[0] = 1;
        final FieldElement fieldElement1 = new Ed25519FieldElement(MathUtils.getField(), t1);
        final FieldElement fieldElement2 = new Ed25519FieldElement(MathUtils.getField(), t2);

        // Act:
        final byte[] bytes1 = MathUtils.getField().getEncoding().encode(fieldElement1);
        final byte[] bytes2 = MathUtils.getField().getEncoding().encode(fieldElement2);

        // Assert:
        Assert.assertThat(bytes1, IsEqual.equalTo(MathUtils.toByteArray(BigInteger.ZERO)));
        Assert.assertThat(bytes2, IsEqual.equalTo(MathUtils.toByteArray(BigInteger.ONE)));
    }

    @Test
    public void encodeReturnsCorrectByteArray() {
        for (int i = 0; 10000 > i; i++){
            // Arrange:
            final int[] t = new int[10];
            for (int j = 0; 10 > j; j++) {
                t[j] = random.nextInt(1 << 28) - (1 << 27);
            }
            final FieldElement fieldElement1 = new Ed25519FieldElement(MathUtils.getField(), t);
            final BigInteger b = toBigInteger(t);

            // Act:
            final byte[] bytes = MathUtils.getField().getEncoding().encode(fieldElement1);

            // Assert:
            Assert.assertThat(bytes, IsEqual.equalTo(MathUtils.toByteArray(b.mod(MathUtils.getQ()))));
        }
    }

    @Test
    public void decodeReturnsCorrectFieldElementForSimpleByteArrays() {
        // Arrange:
        final byte[] bytes1 = new byte[32];
        final byte[] bytes2 = new byte[32];
        bytes2[0] = (byte) 1;

        // Act:
        final Ed25519FieldElement f1 = (Ed25519FieldElement)MathUtils.getField().getEncoding().decode(bytes1);
        final Ed25519FieldElement f2 = (Ed25519FieldElement)MathUtils.getField().getEncoding().decode(bytes2);
        final BigInteger b1 = toBigInteger(f1.t);
        final BigInteger b2 = toBigInteger(f2.t);

        // Assert:
        Assert.assertThat(b1, IsEqual.equalTo(BigInteger.ZERO));
        Assert.assertThat(b2, IsEqual.equalTo(BigInteger.ONE));
    }

    @Test
    public void decodeReturnsCorrectFieldElement() {
        for (int i = 0; 10000 > i; i++) {
            // Arrange:
            final byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            bytes[31] = (byte) (bytes[31] & 0x7f);
            final BigInteger b1 = MathUtils.toBigInteger(bytes);

            // Act:
            final Ed25519FieldElement f = (Ed25519FieldElement)MathUtils.getField().getEncoding().decode(bytes);
            final BigInteger b2 = toBigInteger(f.t).mod(MathUtils.getQ());

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1));
        }
    }

    @Test
    public void isNegativeReturnsCorrectResult() {
        for (int i = 0; 10000 > i; i++) {
            // Arrange:
            final int[] t = new int[10];
            for (int j = 0; 10 > j; j++) {
                t[j] = random.nextInt(1 << 28) - (1 << 27);
            }
            final boolean isNegative = toBigInteger(t).mod(MathUtils.getQ()).mod(new BigInteger("2")).equals(BigInteger.ONE);
            final FieldElement f = new Ed25519FieldElement(MathUtils.getField(), t);

            // Assert:
            Assert.assertThat(MathUtils.getField().getEncoding().isNegative(f), IsEqual.equalTo(isNegative));
        }
    }
}
