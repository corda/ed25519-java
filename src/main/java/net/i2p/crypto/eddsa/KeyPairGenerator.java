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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;
import java.util.Objects;

import net.i2p.crypto.eddsa.spec.EdDSAGenParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.jetbrains.annotations.NotNull;

/**
 *  Default keysize is 256 (Ed25519)
 */
public final class KeyPairGenerator extends KeyPairGeneratorSpi {
    public static final int DEFAULT_KEYSIZE = 256;
    public EdDSAParameterSpec edParams;
    public SecureRandom random;
    public boolean initialized;

    @NotNull
    public static final Hashtable<Integer, AlgorithmParameterSpec> edParameters;

    static {
        edParameters = new Hashtable<>();

        edParameters.put(Integer.valueOf(256), new EdDSAGenParameterSpec(EdDSANamedCurveTable.ED_25519));
    }

    public void initialize(final int keysize, final SecureRandom random) {
        final AlgorithmParameterSpec edParams = edParameters.get(Integer.valueOf(keysize));
        Objects.requireNonNull(edParams);
        try {
            initialize(edParams, random);
        } catch (@NotNull final InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException("key type not configurable.");
        }
    }

    @Override
    public void initialize(final AlgorithmParameterSpec params, final SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params instanceof EdDSAParameterSpec) {
            edParams = (EdDSAParameterSpec) params;
        } else if (params instanceof EdDSAGenParameterSpec) {
            edParams = createNamedCurveSpec(((EdDSAGenParameterSpec) params).getName());
        } else
            throw new InvalidAlgorithmParameterException("parameter object not a EdDSAParameterSpec");

        this.random = random;
        initialized = true;
    }

    public KeyPair generateKeyPair() {
        if (!initialized)
            initialize(DEFAULT_KEYSIZE, new SecureRandom());

        @NotNull final byte[] seed = new byte[edParams.curve.getEdDSAFiniteField().getb()/8];
        random.nextBytes(seed);

        @NotNull final EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(seed, edParams);
        @NotNull final EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(privKey.groupElement, edParams);

        return new KeyPair(new EdDSAPublicKey(pubKey), new EdDSAPrivateKey(privKey));
    }

    /**
     * Create an EdDSANamedCurveSpec from the provided curve name. The current
     * implementation fetches the pre-created curve spec from a table.
     * @param curveName the EdDSA named curve.
     * @return the specification for the named curve.
     * @throws InvalidAlgorithmParameterException if the named curve is unknown.
     */
    protected EdDSANamedCurveSpec createNamedCurveSpec(@NotNull final String curveName) {
        final EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName(curveName);
        Objects.requireNonNull(spec);
        return spec;
    }
}
