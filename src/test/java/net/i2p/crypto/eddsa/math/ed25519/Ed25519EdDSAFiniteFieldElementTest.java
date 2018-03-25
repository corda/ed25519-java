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
import org.hamcrest.core.*;
import org.jetbrains.annotations.NotNull;
import org.junit.*;

import java.math.BigInteger;

/**
 * Tests rely on the BigInteger class.
 */
public class Ed25519EdDSAFiniteFieldElementTest extends AbstractEdDSAFiniteFieldElementTest {

    @NotNull
    protected FieldElement getRandomFieldElement() {
        return MathUtils.getRandomFieldElement();
    }

    protected BigInteger toBigInteger(@NotNull final FieldElement f) {
        return MathUtils.toBigInteger(f);
    }

    @NotNull
    protected BigInteger getQ() {
        return MathUtils.getQ();
    }

    @NotNull
    protected EdDSAFiniteField getEdDSAFiniteField() {
        return MathUtils.getEdDSAFiniteField();
    }

    // region constructor

    @Test
    public void canConstructFieldElementFromArrayWithCorrectLength() {
        // Assert:
        new Ed25519FieldElement(MathUtils.getEdDSAFiniteField(), new int[10]);
    }

    @Test (expected = AssertionError.class)
    public void cannotConstructFieldElementFromArrayWithIncorrectLength() {
        // Assert:
        new Ed25519FieldElement(MathUtils.getEdDSAFiniteField(), new int[9]);
    }

    @Test (expected = AssertionError.class)
    public void cannotConstructFieldElementWithoutField() {
        // Assert:
        new Ed25519FieldElement(null, new int[9]);
    }

    // endregion

    // region isNonZero

    @NotNull
    protected FieldElement getZeroFieldElement() {
        return new Ed25519FieldElement(MathUtils.getEdDSAFiniteField(), new int[10]);
    }

    @NotNull
    protected FieldElement getNonZeroFieldElement() {
        @NotNull final int[] t = new int[10];
        t[0] = 5;
        return new Ed25519FieldElement(MathUtils.getEdDSAFiniteField(), t);
    }

    // endregion

    // region toString

    @Test
    public void toStringReturnsCorrectRepresentation() {
        // Arrange:
        @NotNull final byte[] bytes = new byte[32];
        for (int i = 0; 32 > i; i++) {
            bytes[i] = (byte)(i+1);
        }
        @NotNull final FieldElement f = MathUtils.getEdDSAFiniteField().getEncoding().decode(bytes);

        // Act:
        final String fAsString = f.toString();
        @NotNull final StringBuilder builder = new StringBuilder();
        builder.append("[Ed25519FieldElement val=");
        for (final byte b : bytes) {
            builder.append(String.format("%02x", Byte.valueOf(b)));
        }
        builder.append("]");

        // Assert:
        Assert.assertThat(fAsString, IsEqual.equalTo(builder.toString()));
    }

    // endregion
}
