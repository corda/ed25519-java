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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Objects;

import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.jetbrains.annotations.NotNull;

/**
 * @author str4d
 *
 */
public final class KeyFactory extends KeyFactorySpi {

    @NotNull
    protected PrivateKey engineGeneratePrivate(final KeySpec keySpec) throws InvalidKeySpecException {
        @NotNull final EdDSAPrivateKey ret;
        if (keySpec instanceof EdDSAPrivateKeySpec)
            ret = new EdDSAPrivateKey((EdDSAPrivateKeySpec) keySpec);
        else {
            assert keySpec instanceof PKCS8EncodedKeySpec : "key spec not recognised: " + keySpec.getClass();
            ret = new EdDSAPrivateKey((PKCS8EncodedKeySpec) keySpec);
        }
        return ret;
    }

    protected PublicKey engineGeneratePublic(final KeySpec keySpec) {
        assert keySpec instanceof EdDSAPublicKeySpec : "key spec not recognised: " + keySpec.getClass();
        return new EdDSAPublicKey((EdDSAPublicKeySpec) keySpec);
    }

    @NotNull
    @SuppressWarnings("unchecked")
    protected <T extends KeySpec> T engineGetKeySpec(final Key key, final Class<T> keySpec) {
        @NotNull final T ret;
        if (!keySpec.isAssignableFrom(EdDSAPublicKeySpec.class) || !(key instanceof EdDSAPublicKey)) {
            assert keySpec.isAssignableFrom(EdDSAPrivateKeySpec.class) && key instanceof EdDSAPrivateKey : "not implemented yet " + key + " " + keySpec;
            @NotNull final EdDSAPrivateKey k = (EdDSAPrivateKey) key;
            ret=(T) new EdDSAPrivateKeySpec(k.getSeed(), k.getHashOfTheSeed(), k.getPrivateKey(), k.getGroupElement(), k.getEdDSAParameterSpec());
        } else {
            @NotNull final EdDSAPublicKey k = (EdDSAPublicKey) key;
            Objects.requireNonNull(k.getEdDSAParameterSpec());
            ret=(T) new EdDSAPublicKeySpec(k.getA(), k.getEdDSAParameterSpec());
        }
        return ret;
    }

    @NotNull
    protected Key engineTranslateKey(final Key key) throws InvalidKeyException {
        throw new InvalidKeyException("No other EdDSA key providers known");
    }
}
