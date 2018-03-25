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

import java.util.HashMap;
import java.util.Locale;
import java.util.Objects;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.BaseCurve;
import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.EdDSAFiniteField;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519ScalarOps;
import org.jetbrains.annotations.NotNull;

/**
 * The named EdDSA curves.
 * @author str4d
 *
 */
public class EdDSANamedCurveTable {
    public static final String ED_25519 = "Ed25519";

    private static final EdDSAFiniteField ED_25519_ED_DSA_FINITE_FIELD = new EdDSAFiniteField(
                    256, // b
                    Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
            new Ed25519LittleEndianEncoding().getEmptyEncoding());

    private static final Curve ed25519curve = createBaseCurve(ED_25519_ED_DSA_FINITE_FIELD,
            Utils.hexToBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"), // d
            ED_25519_ED_DSA_FINITE_FIELD.fromByteArray(Utils.hexToBytes("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"))); // I

//    public static final EdDSANamedCurveSpec ED_25519 = ; // Precompute tables for B

    @NotNull
    private static volatile HashMap<String, EdDSANamedCurveSpec> curves = new HashMap<>();

    private static synchronized void putCurve(final String name, final EdDSANamedCurveSpec curve) {
        @NotNull final HashMap<String, EdDSANamedCurveSpec> newCurves = new HashMap<>(curves);
        newCurves.put(name, curve);
        curves = newCurves;
    }

    private static void defineCurve(@NotNull final EdDSANamedCurveSpec curve) {
        putCurve(curve.getName().toLowerCase(Locale.ENGLISH), curve);
    }

    static void defineCurveAlias(final String name, final String alias) {
        final EdDSANamedCurveSpec curve = curves.get(name.toLowerCase(Locale.ENGLISH));
        Objects.requireNonNull(curve);
        putCurve(alias.toLowerCase(Locale.ENGLISH), curve);
    }

    static {
        // RFC 8032
        defineCurve(new EdDSANamedCurveSpec(
                ED_25519,
                ed25519curve,
                "SHA-512", // H
                new Ed25519ScalarOps(), // l
                ed25519curve.createPoint( // B
                        Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"),
                        true)));
    }

    public static EdDSANamedCurveSpec getByName(final String name) {
        return curves.get(name.toLowerCase(Locale.ENGLISH));
    }

    public static BaseCurve createBaseCurve(EdDSAFiniteField edDSAFiniteField, byte[] fieldElementD, FieldElement fieldElementI) {
        FieldElement fieldElementD1 = edDSAFiniteField.fromByteArray(fieldElementD);
        FieldElement add = fieldElementD1.add(fieldElementD1);
        return new BaseCurve(  edDSAFiniteField, fieldElementD1, add, fieldElementI);

    }
}
