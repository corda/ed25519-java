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
package net.i2p.crypto.eddsa;

import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * An EdDSA public key.
 *<p>
 * Warning: Public key encoding is is based on the current curdle WG draft,
 * and is subject to change. See getEncoded().
 *</p><p>
 * For compatibility with older releases, decoding supports both the old and new
 * draft specifications. See decode().
 *</p><p>
 * Ref: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
 *</p><p>
 * Old Ref: https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04
 *</p>
 * @author str4d
 *
 */
public class EdDSAPublicKey implements EdDSAKey, PublicKey {

    // OID 1.3.101.xxx
    private static final int OID_OLD = 100;
    private static final int OID_ED25519 = 112;
    private static final int OID_BYTE = 8;
    private static final int IDLEN_BYTE = 3;
    private final GroupElement A;
    @Nullable
    private final GroupElement aNeg;
    private final byte[] aByte;
    private final EdDSAParameterSpec edDSAParameterSpec;

    public EdDSAPublicKey(final EdDSAPublicKeySpec spec) {
        this.A = spec.A;
        this.aNeg = spec.getNegativeA();
        this.aByte = this.getA().toByteArray();
        this.edDSAParameterSpec = spec.getParams();
    }

    public EdDSAPublicKey(final X509EncodedKeySpec spec) throws InvalidKeySpecException {
        this(new EdDSAPublicKeySpec(decode(spec.getEncoded()),
                EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)));
    }

    /**
     * Extracts the public key bytes from the provided encoding.
     *<p>
     * This will decode data conforming to the current spec at
     * https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
     * or the old spec at
     * https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04.
     *</p><p>
     * Contrary to draft-ietf-curdle-pkix-04, it WILL accept a parameter value
     * of NULL, as it is required for interoperability with the default Java
     * keystore. Other implementations MUST NOT copy this behaviour from here
     * unless they also need to read keys from the default Java keystore.
     *</p><p>
     * This is really dumb for now. It does not use a general-purpose ASN.1 decoder.
     * See also getEncoded().
     *</p>
     *
     * @return 32 bytes for Ed25519, throws for other curves
     */
    @NotNull
    private static byte[] decode(final byte[] d) throws InvalidKeySpecException {
        try {
            //
            // Setup and OID check
            //
            int totlen = 44;
            int idlen = 5;
            final int doid = d[OID_BYTE];
            switch (doid) {
                case OID_OLD:
                    totlen = 47;
                    idlen = 8;
                    break;
                case OID_ED25519:
                    // Detect parameter value of NULL
                    if (7 == d[IDLEN_BYTE]) {
                        totlen = 46;
                        idlen = 7;
                    }
                    break;
                default:
                    throw new InvalidKeySpecException("unsupported key spec");
            }

            //
            // Pre-decoding check
            //
            assert d.length == totlen : "invalid key spec length";

            //
            // Decoding
            //
            int idx = 0;
            assert 0x30 == d[idx++] &&
                    d[idx++] == (totlen - 2) &&
                    0x30 == d[idx++] &&
                    d[idx++] == idlen &&
                    0x06 == d[idx++] &&
                    3 == d[idx++] &&
                    (1 * 40) + 3 == d[idx++] &&
                    101 == d[idx++] : "unsupported key spec";
            idx++; // OID, checked above
            // parameters only with old OID
            if (OID_OLD == doid) {
                assert 0x0a == d[idx++] &&
                        1 == d[idx++] &&
                        1 == d[idx++] : "unsupported key spec";
            } else {
                // Handle parameter value of NULL
                //
                // Quote https://tools.ietf.org/html/draft-ietf-curdle-pkix-04 :
                //   For all of the OIDs, the parameters MUST be absent.
                //   Regardless of the defect in the original 1997 syntax,
                //   implementations MUST NOT accept a parameters value of NULL.
                //
                // But Java's default keystore puts it in (when decoding as
                // PKCS8 and then re-encoding to pass on), so we must accept it.
                if (7 == idlen) {
                    assert 0x05 == d[idx++] &&
                            0 == d[idx++] : "unsupported key spec";
                }
            }
            assert 0x03 == d[idx++] &&
                    33 == d[idx++] &&
                    0 == d[idx++] : "unsupported key spec";
            @NotNull final byte[] rv = new byte[32];
            System.arraycopy(d, idx, rv, 0, 32);
            return rv;
        } catch (@NotNull final IndexOutOfBoundsException ioobe) {
            throw new InvalidKeySpecException(ioobe);
        }
    }

    @NotNull
    @Override
    public String getAlgorithm() {
        return KEY_ALGORITHM;
    }

    @NotNull
    @Override
    public String getFormat() {
        return "X.509";
    }

    /**
     * Returns the public key in its canonical encoding.
     *<p>
     * This implements the following specs:
     *<ul><li>
     * General encoding: https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
     *</li><li>
     * Key encoding: https://tools.ietf.org/html/rfc8032
     *</li></ul>
     *<p>
     * For keys in older formats, decoding and then re-encoding is sufficient to
     * migrate them to the canonical encoding.
     *</p>
     * Relevant spec quotes:
     *<pre>
     *  In the X.509 certificate, the subjectPublicKeyInfo field has the
     *  SubjectPublicKeyInfo type, which has the following ASN.1 syntax:
     *
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *    algorithm         AlgorithmIdentifier,
     *    subjectPublicKey  BIT STRING
     *  }
     *</pre>
     *
     *<pre>
     *  AlgorithmIdentifier  ::=  SEQUENCE  {
     *    algorithm   OBJECT IDENTIFIER,
     *    parameters  ANY DEFINED BY algorithm OPTIONAL
     *  }
     *
     *  For all of the OIDs, the parameters MUST be absent.
     *</pre>
     *
     *<pre>
     *  id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
     *</pre>
     *
     * @return 44 bytes for Ed25519, null for other curves
     */
    @Nullable
    @Override
    public byte[] getEncoded() {
        if (getEdDSAParameterSpec() instanceof EdDSANamedCurveSpec && ((EdDSANamedCurveSpec) getEdDSAParameterSpec()).getName().equals(EdDSANamedCurveTable.ED_25519)) {

            final int totlen = 12 + getaByte().length;
            @NotNull final byte[] rv = new byte[totlen];
            int idx = 0;
            // sequence
            rv[idx++] = (byte) 0x30;
            rv[idx++] = (byte) (totlen - 2);
            // Algorithm Identifier
            // sequence
            rv[idx++] = (byte) 0x30;
            rv[idx++] = (byte) 5;
            // OID
            // https://msdn.microsoft.com/en-us/library/windows/desktop/bb540809%28v=vs.85%29.aspx
            rv[idx++] = (byte) 0x06;
            rv[idx++] = (byte) 3;
            rv[idx++] = (byte) ((1 * 40) + 3);
            rv[idx++] = (byte) 101;
            rv[idx++] = (byte) OID_ED25519;
            // params - absent
            // the key
            rv[idx++] = (byte) 0x03; // bit string
            rv[idx++] = (byte) (1 + getaByte().length);
            rv[idx++] = (byte) 0; // number of trailing unused bits
            System.arraycopy(getaByte(), 0, rv, idx, getaByte().length);
            return rv;
        }
        return null;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getaByte());
    }

    @Override
    public boolean equals(final Object o) {
        if (o == this)
            return true;
        if (!(o instanceof EdDSAPublicKey))
            return false;
        @NotNull final EdDSAPublicKey pk = (EdDSAPublicKey) o;
        return Arrays.equals(getaByte(), pk.getaByte()) &&
                getEdDSAParameterSpec().equals(pk.getEdDSAParameterSpec());
    }

    @Override
    public EdDSAParameterSpec getEdDSAParameterSpec() {
        return edDSAParameterSpec;
    }

    public GroupElement getA() {
        return A;
    }

    @Nullable
    public GroupElement getaNeg() {
        return aNeg;
    }

    public byte[] getaByte() {
        return aByte;
    }
}
