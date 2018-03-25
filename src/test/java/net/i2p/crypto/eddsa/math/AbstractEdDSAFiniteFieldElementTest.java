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

import org.hamcrest.core.*;
import org.jetbrains.annotations.NotNull;
import org.junit.*;

import java.math.BigInteger;

/**
 * Tests rely on the BigInteger class.
 */
public abstract class AbstractEdDSAFiniteFieldElementTest {

    @NotNull
    protected abstract FieldElement getRandomFieldElement();
    protected abstract BigInteger toBigInteger(FieldElement f);
    @NotNull
    protected abstract BigInteger getQ();
    @NotNull
    protected abstract EdDSAFiniteField getEdDSAFiniteField();

    // region isNonZero

    @NotNull
    protected abstract FieldElement getZeroFieldElement();
    @NotNull
    protected abstract FieldElement getNonZeroFieldElement();

    @Test
    public void isNonZeroReturnsFalseIfFieldElementIsZero() {
        // Act:
        @NotNull final FieldElement f = getZeroFieldElement();

        // Assert:
        Assert.assertThat(Boolean.valueOf(f.isNonZero()), IsEqual.equalTo(Boolean.FALSE));
    }

    @Test
    public void isNonZeroReturnsTrueIfFieldElementIsNonZero() {
        // Act:
        @NotNull final FieldElement f = getNonZeroFieldElement();

        // Assert:
        Assert.assertThat(Boolean.valueOf(f.isNonZero()), IsEqual.equalTo(Boolean.TRUE));
    }

    // endregion

    // region mod q arithmetic

    @Test
    public void addReturnsCorrectResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            @NotNull final FieldElement f1 = getRandomFieldElement();
            @NotNull final FieldElement f2 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);
            final BigInteger b2 = toBigInteger(f2);

            // Act:
            @NotNull final FieldElement f3 = f1.add(f2);
            final BigInteger b3 = toBigInteger(f3).mod(getQ());

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.add(b2).mod(getQ())));
        }
    }

    @Test
    public void subtractReturnsCorrectResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            @NotNull final FieldElement f1 = getRandomFieldElement();
            @NotNull final FieldElement f2 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);
            final BigInteger b2 = toBigInteger(f2);

            // Act:
            @NotNull final FieldElement f3 = f1.subtract(f2);
            final BigInteger b3 = toBigInteger(f3).mod(getQ());

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.subtract(b2).mod(getQ())));
        }
    }

    @Test
    public void negateReturnsCorrectResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            @NotNull final FieldElement f1 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);

            // Act:
            final FieldElement f2 = f1.negate();
            final BigInteger b2 = toBigInteger(f2).mod(getQ());

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.negate().mod(getQ())));
        }
    }

    @Test
    public void multiplyReturnsCorrectResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            @NotNull final FieldElement f1 = getRandomFieldElement();
            @NotNull final FieldElement f2 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);
            final BigInteger b2 = toBigInteger(f2);

            // Act:
            @NotNull final FieldElement f3 = f1.multiply(f2);
            final BigInteger b3 = toBigInteger(f3).mod(getQ());

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.multiply(b2).mod(getQ())));
        }
    }

    @Test
    public void squareReturnsCorrectResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            @NotNull final FieldElement f1 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);

            // Act:
            @NotNull final FieldElement f2 = f1.square();
            final BigInteger b2 = toBigInteger(f2).mod(getQ());

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.multiply(b1).mod(getQ())));
        }
    }

    @Test
    public void squareAndDoubleReturnsCorrectResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            @NotNull final FieldElement f1 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);

            // Act:
            final FieldElement f2 = f1.squareAndDouble();
            final BigInteger b2 = toBigInteger(f2).mod(getQ());

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.multiply(b1).multiply(new BigInteger("2")).mod(getQ())));
        }
    }

    @Test
    public void invertReturnsCorrectResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            @NotNull final FieldElement f1 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);

            // Act:
            final FieldElement f2 = f1.invert();
            final BigInteger b2 = toBigInteger(f2).mod(getQ());

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.modInverse(getQ())));
        }
    }

    @Test
    public void pow22523ReturnsCorrectResult() {
        for (int i = 0; 1000 > i; i++) {
            // Arrange:
            @NotNull final FieldElement f1 = getRandomFieldElement();
            final BigInteger b1 = toBigInteger(f1);

            // Act:
            @NotNull final FieldElement f2 = f1.pow22523();
            final BigInteger b2 = toBigInteger(f2).mod(getQ());

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.modPow(BigInteger.ONE.shiftLeft(252).subtract(new BigInteger("3")), getQ())));
        }
    }

    // endregion

    // region cmov

    @Test
    public void cmovReturnsCorrectResult() {
        @NotNull final FieldElement zero = getZeroFieldElement();
        @NotNull final FieldElement nz = getNonZeroFieldElement();
        @NotNull final FieldElement f = getRandomFieldElement();

        Assert.assertThat(zero.cmov(nz, 0), IsEqual.equalTo(zero));
        Assert.assertThat(zero.cmov(nz, 1), IsEqual.equalTo(nz));

        Assert.assertThat(f.cmov(nz, 0), IsEqual.equalTo(f));
        Assert.assertThat(f.cmov(nz, 1), IsEqual.equalTo(nz));
    }

    // endregion

    // region hashCode / equals

    @Test
    public void equalsOnlyReturnsTrueForEquivalentObjects() {
        // Arrange:
        @NotNull final FieldElement f1 = getRandomFieldElement();
        @NotNull final FieldElement f2 = getEdDSAFiniteField().getEncoding().decode(f1.toByteArray());
        @NotNull final FieldElement f3 = getRandomFieldElement();
        @NotNull final FieldElement f4 = getRandomFieldElement();

        // Assert:
        Assert.assertThat(f1, IsEqual.equalTo(f2));
        Assert.assertThat(f1, IsNot.not(IsEqual.equalTo(f3)));
        Assert.assertThat(f1, IsNot.not(IsEqual.equalTo(f4)));
        Assert.assertThat(f3, IsNot.not(IsEqual.equalTo(f4)));
    }

    @Test
    public void hashCodesAreEqualForEquivalentObjects() {
        // Arrange:
        @NotNull final FieldElement f1 = getRandomFieldElement();
        @NotNull final FieldElement f2 = getEdDSAFiniteField().getEncoding().decode(f1.toByteArray());
        @NotNull final FieldElement f3 = getRandomFieldElement();
        @NotNull final FieldElement f4 = getRandomFieldElement();

        // Assert:
        Assert.assertThat(Integer.valueOf(f1.hashCode()), IsEqual.equalTo(Integer.valueOf(f2.hashCode())));
        Assert.assertThat(Integer.valueOf(f1.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(f3.hashCode()))));
        Assert.assertThat(Integer.valueOf(f1.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(f4.hashCode()))));
        Assert.assertThat(Integer.valueOf(f3.hashCode()), IsNot.not(IsEqual.equalTo(Integer.valueOf(f4.hashCode()))));
    }

    // endregion
}
