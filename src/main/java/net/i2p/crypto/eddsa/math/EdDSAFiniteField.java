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

/**
 * An EdDSA finite field. Includes several pre-computed values.
 * @author str4d
 *
 */
@SuppressWarnings("ThisEscapedInObjectConstruction")
public class EdDSAFiniteField  {

    public final FieldElement ZERO;
    public final FieldElement ONE;
    public final FieldElement TWO;
    private final FieldElement FOUR;
    private final FieldElement FIVE;
    private final FieldElement EIGHT;

    private final int b;
    private final FieldElement q;
    /**
     * q-2
     */
    private final FieldElement qm2;
    /**
     * (q-5) / 8
     */
    private final FieldElement qm5d8;
    private final EmptyEncoding enc;

    public EdDSAFiniteField(final int b, final byte[] q, final EmptyEncoding enc) {
        this.b = b;
        this.enc = enc;
        this.enc.setEdDSAFiniteField(this);

        this.q = fromByteArray(q);

        // Set up constants
        ZERO = fromByteArray(Constants.ZERO);
        ONE = fromByteArray(Constants.ONE);
        TWO = fromByteArray(Constants.TWO);
        FOUR = fromByteArray(Constants.FOUR);
        FIVE = fromByteArray(Constants.FIVE);
        EIGHT = fromByteArray(Constants.EIGHT);

        // Precompute values
        qm2 = this.q.subtract(TWO);
        qm5d8 = this.q.subtract(FIVE).divide(EIGHT);
    }

    public FieldElement fromByteArray(final byte[] x) {
        return enc.decode(x);
    }

    public int getb() {
        return b;
    }

    public FieldElement getQ() {
        return q;
    }

    public FieldElement getQm2() {
        return qm2;
    }

    public FieldElement getQm5d8() {
        return qm5d8;
    }

    public Encoding getEncoding(){
        return enc;
    }

    @Override
    public int hashCode() {
        return q.hashCode();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof EdDSAFiniteField))
            return false;
        final EdDSAFiniteField f = (EdDSAFiniteField) obj;
        return b == f.b && q.equals(f.q);
    }
}
