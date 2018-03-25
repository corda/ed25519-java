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
package net.i2p.crypto.eddsa.spec;

import java.security.spec.KeySpec;

import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.math.P3GroupElement;
import org.jetbrains.annotations.Nullable;

/**
 * @author str4d
 *
 */
public class EdDSAPublicKeySpec implements KeySpec {
    public final GroupElement A;
    @Nullable
    private GroupElement Aneg = null;
    private final EdDSAParameterSpec spec;

    /**
     * @param pk the public key
     * @param spec the parameter specification for this key
     * @throws IllegalArgumentException if key length is wrong
     */
    public EdDSAPublicKeySpec(final byte[] pk, final EdDSAParameterSpec spec) {
        assert pk.length == spec.curve.getEdDSAFiniteField().getb() / 8 : "public-key length is wrong";

        this.A = new P3GroupElement(spec.curve, pk);
        this.spec = spec;
    }

    public EdDSAPublicKeySpec(final GroupElement A, final EdDSAParameterSpec spec) {
        this.A = A;
        this.spec = spec;
    }

    @Nullable
    public GroupElement getNegativeA() {
        // Only read Aneg once, otherwise read re-ordering might occur between here and return. Requires all GroupElement's fields to be final.
        @Nullable GroupElement ourAneg = Aneg;
        if(null == ourAneg) {
            ourAneg = A.negate();
            Aneg = ourAneg;
        }
        return ourAneg;
    }

    public EdDSAParameterSpec getParams() {
        return spec;
    }
}
