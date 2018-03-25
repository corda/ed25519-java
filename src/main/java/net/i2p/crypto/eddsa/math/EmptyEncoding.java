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
 * Common interface for all $(b-1)$-bit encodings of elements
 * of EdDSA finite fields.
 * @author str4d
 *
 */
public abstract   class EmptyEncoding implements Encoding {
    private EdDSAFiniteField edDSAFiniteField;

    public synchronized void setEdDSAFiniteField(final EdDSAFiniteField f) {
        //noinspection IfCanBeAssertion
        if (null != this.getEdDSAFiniteField()) throw new IllegalStateException("already set");
        edDSAFiniteField = f;

    }

    public EdDSAFiniteField getEdDSAFiniteField() {
        return edDSAFiniteField;
    }
}
