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
package net.i2p.crypto.eddsa;

import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * An EdDSA private key.
 *<p>
 * Warning: Private key encoding is based on the current curdle WG draft,
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
public class EdDSAPrivateKey implements EdDSAKey, PrivateKey {

    @Nullable
    private final byte[] seed;
    private final byte[] hashOfTheSeed;
    private final byte[] privateKey;
    private final GroupElement groupElement;
    private final byte[] aByte;
    private final EdDSAParameterSpec edDSAParameterSpec;

    // OID 1.3.101.xxx
    private static final int OID_OLD = 100;
    private static final int OID_ED25519 = 112;
    private static final int OID_BYTE = 11;
    private static final int IDLEN_BYTE = 6;

    public EdDSAPrivateKey(final EdDSAPrivateKeySpec spec) {
        seed = spec.seed;
        hashOfTheSeed = spec.hashOfTheSeed;
        privateKey = spec.privateKey;
        groupElement = spec.groupElement;
        aByte = getGroupElement().toByteArray();
        edDSAParameterSpec = spec.getParams();
    }

    public EdDSAPrivateKey(final PKCS8EncodedKeySpec spec) throws InvalidKeySpecException {
        this(new EdDSAPrivateKeySpec(decode(spec.getEncoded()),
                                     EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)));
    }

    @NotNull
    @Override
    public String getAlgorithm() {
        return KEY_ALGORITHM;
    }

    @NotNull
    @Override
    public String getFormat() {
        return "PKCS#8";
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
     * This encodes the seed. It will return null if constructed from
     * a spec which was directly constructed from H, in which case seed is null.
     *</p><p>
     * For keys in older formats, decoding and then re-encoding is sufficient to
     * migrate them to the canonical encoding.
     *</p>
     * Relevant spec quotes:
     *<pre>
     *  OneAsymmetricKey ::= SEQUENCE {
     *    version Version,
     *    privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
     *    privateKey PrivateKey,
     *    attributes [0] Attributes OPTIONAL,
     *    ...,
     *    [[2: publicKey [1] PublicKey OPTIONAL ]],
     *    ...
     *  }
     *
     *  Version ::= INTEGER
     *  PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     *  PrivateKey ::= OCTET STRING
     *  PublicKey ::= OCTET STRING
     *  Attributes ::= SET OF Attribute
     *</pre>
     *
     *<pre>
     *  ... when encoding a OneAsymmetricKey object, the private key is wrapped
     *  in a CurvePrivateKey object and wrapped by the OCTET STRING of the
     *  'privateKey' field.
     *
     *  CurvePrivateKey ::= OCTET STRING
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
     * @return 48 bytes for Ed25519, null for other curves
     */
    @Nullable
    @Override
    public byte[] getEncoded() {
        if (!getEdDSAParameterSpec().equals(EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)))
            return null;
        if (null == getSeed())
            return null;
        final int totlen = 16 + getSeed().length;
        @NotNull final byte[] encoded = new byte[totlen];
        int idx = 0;
        // sequence
        encoded[idx++] = (byte) 0x30;
        encoded[idx++] = (byte) (totlen - 2);
        // version
        encoded[idx++] = (byte) 0x02;
        encoded[idx++] = (byte) 1;
        // v1 - no public key included
        encoded[idx++] = (byte) 0;
        // Algorithm Identifier
        // sequence
        encoded[idx++] = (byte) 0x30;
        encoded[idx++] = (byte) 5;
        // OID
        // https://msdn.microsoft.com/en-us/library/windows/desktop/bb540809%28v=vs.85%29.aspx
        encoded[idx++] = (byte) 0x06;
        encoded[idx++] = (byte) 3;
        encoded[idx++] = (byte) ((1 * 40) + 3);
        encoded[idx++] = (byte) 101;
        encoded[idx++] = (byte) OID_ED25519;
        // params - absent
        // PrivateKey
        encoded[idx++] = (byte) 0x04;  // octet string
        encoded[idx++] = (byte) (2 + getSeed().length);
        // CurvePrivateKey
        encoded[idx++] = (byte) 0x04;  // octet string
        encoded[idx++] = (byte) getSeed().length;
        // the key
        System.arraycopy(getSeed(), 0, encoded, idx, getSeed().length);
        return  encoded;
    }

    /**
     * Extracts the private key bytes from the provided encoding.
     *<p>
     * This will decode data conforming to the current spec at
     * https://tools.ietf.org/html/draft-ietf-curdle-pkix-04
     * or as inferred from the old spec at
     * https://tools.ietf.org/html/draft-josefsson-pkix-eddsa-04.
     *</p><p>
     * Contrary to draft-ietf-curdle-pkix-04, it WILL accept a parameter value
     * of NULL, as it is required for interoperability with the default Java
     * keystore. Other implementations MUST NOT copy this behaviour from here
     * unless they also need to read keys from the default Java keystore.
     *</p><p>
     * This is really dumb for now. It does not use a general-purpose ASN.1 decoder.
     * See also getEncoded().
     *
     * @return 32 bytes for Ed25519, throws for other curves
     */
    @NotNull
    private static byte[] decode(final byte[] d) throws InvalidKeySpecException {
        try {
            //
            // Setup and OID check
            //
            int totlen = 48;
            int idlen = 5;
            final int doid = d[OID_BYTE];
            switch (doid) {
                case OID_OLD:
                    totlen = 49;
                    idlen = 8;
                    break;
                case OID_ED25519:
                    // Detect parameter value of NULL
                    if (7 == d[IDLEN_BYTE]) {
                        totlen = 50;
                        idlen = 7;
                    }
                    break;
                default:
                    throw new InvalidKeySpecException("unsupported key spec");
            }

            //
            // Pre-decoding check
            //
            if (d.length == totlen) {

                //
                // Decoding
                //
                int idx = 0;
                if (0x30 == d[idx++] &&
                        d[idx++] == (totlen - 2) &&
                        0x02 == d[idx++] &&
                        1 == d[idx++] &&
                        0 == d[idx++] &&
                        0x30 == d[idx++] &&
                        d[idx++] == idlen &&
                        0x06 == d[idx++] &&
                        3 == d[idx++] &&
                        (1 * 40) + 3 == d[idx++] &&
                        101 == d[idx++]) {
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
                        // PrivateKey wrapping the CurvePrivateKey
                        assert 0x04 == d[idx++] &&
                                34 == d[idx++] : "unsupported key spec";
                    }
                    if (0x04 == d[idx++] &&
                            32 == d[idx++]) {
                        @NotNull final byte[] rv = new byte[32];
                        System.arraycopy(d, idx, rv, 0, 32);
                        return rv;
                    }
                    throw new InvalidKeySpecException("unsupported key spec");
                }
                throw new InvalidKeySpecException("unsupported key spec");
            }
            throw new InvalidKeySpecException("invalid key spec length");
        } catch (@NotNull final IndexOutOfBoundsException ioobe) {
            throw new InvalidKeySpecException(ioobe);
        }
    }

    @Override
    public EdDSAParameterSpec getEdDSAParameterSpec() {
        return edDSAParameterSpec;
    }

    /**
     *  @return the public key
     */
    public byte[] getaByte() {
        return aByte.clone();
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getSeed());
    }

    @Override
    public boolean equals(final Object o) {
        return o == this || (o instanceof EdDSAPrivateKey) && Arrays.equals(getSeed(), ((EdDSAPrivateKey) o).getSeed()) && Objects.equals(getEdDSAParameterSpec(), ((EdDSAPrivateKey) o).getEdDSAParameterSpec());
    }

    @Nullable
    public byte[] getSeed() {
        return seed;
    }

    public byte[] getHashOfTheSeed() {
        return hashOfTheSeed;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public GroupElement getGroupElement() {
        return groupElement;
    }
}
