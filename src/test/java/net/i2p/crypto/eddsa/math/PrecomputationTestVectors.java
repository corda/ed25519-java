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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

class PrecomputationTestVectors {
    // Test files were generated using base.py and base2.py from ref10
    // (by printing hex(x%q) instead of the radix-255 representation).
    static final GroupElement[][] testPrecmp = getPrecomputation("basePrecmp");
    static final GroupElement[] testDblPrecmp = getDoublePrecomputation("baseDblPrecmp");

    @NotNull
    private static GroupElement[][] getPrecomputation(final String fileName) {
        final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        @NotNull final Curve curve = ed25519.curve;
        final EdDSAFiniteField edDSAFiniteField = curve.getEdDSAFiniteField();
        @NotNull final GroupElement[][] precmp = new GroupElement[32][8];
        @Nullable BufferedReader file = null;
        int row = 0;
        int col = 0;
        try {
            final InputStream is = PrecomputationTestVectors.class.getResourceAsStream(fileName);
            if (null == is)
                throw new IOException("Resource not found: " + fileName);
            file = new BufferedReader(new InputStreamReader(is));
            while (true) {
                String  line = file.readLine();
                if ((null != (line))) {
                    if (!" },".equals(line)) {
                        if (!"},".equals(line)) {
                            if (line.startsWith("  { ")) {
                                @NotNull final String ypxStr = line.substring(4, line.lastIndexOf(' '));
                                @NotNull final FieldElement ypx = edDSAFiniteField.fromByteArray(
                                        Utils.hexToBytes(ypxStr));
                                String s = file.readLine();
                                @NotNull final String ymxStr = s.substring(4, s.lastIndexOf(' '));
                                @NotNull final FieldElement ymx = edDSAFiniteField.fromByteArray(
                                        Utils.hexToBytes(ymxStr));
                                String s3 = file.readLine();
                                @NotNull final String xy2dStr = s3.substring(4, s3.lastIndexOf(' '));
                                @NotNull final FieldElement xy2d = edDSAFiniteField.fromByteArray(
                                        Utils.hexToBytes(xy2dStr));
                                precmp[row][col] = new PrecompGroupElement(curve, ypx, ymx, xy2d);
                            }
                        } else {
                            col = 0;
                            row += 1;
                        }
                    } else {
                        col += 1;
                    }
                } else {
                    break;
                }
            }
        } catch (@NotNull final IOException e) {
            e.printStackTrace();
        } finally {
            if (null != file) try { file.close(); } catch (@NotNull final IOException e) {}
        }
        return precmp;
    }

    @NotNull
    private static GroupElement[] getDoublePrecomputation(final String fileName) {
        final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        @NotNull final Curve curve = ed25519.curve;
        final EdDSAFiniteField edDSAFiniteField = curve.getEdDSAFiniteField();
        @NotNull final GroupElement[] dblPrecmp = new GroupElement[8];
        @Nullable BufferedReader file = null;
        int row = 0;
        try {
            final InputStream is = PrecomputationTestVectors.class.getResourceAsStream(fileName);
            if (null == is)
                throw new IOException("Resource not found: " + fileName);
            file = new BufferedReader(new InputStreamReader(is));
            while (true) {
                String  line = file.readLine();
                if ((null != line)) {
                    if (!" },".equals(line)) {
                        if (line.startsWith("  { ")) {
                            @NotNull final String ypxStr = line.substring(4, line.lastIndexOf(' '));
                            @NotNull final FieldElement ypx = edDSAFiniteField.fromByteArray(
                                    Utils.hexToBytes(ypxStr));
                            String s2 = file.readLine();
                            @NotNull final String ymxStr = s2.substring(4, s2.lastIndexOf(' '));
                            @NotNull final FieldElement ymx = edDSAFiniteField.fromByteArray(
                                    Utils.hexToBytes(ymxStr));
                            String s4 = file.readLine();
                            @NotNull final String xy2dStr = s4.substring(4, s4.lastIndexOf(' '));
                            @NotNull final FieldElement xy2d = edDSAFiniteField.fromByteArray(
                                    Utils.hexToBytes(xy2dStr));
                            dblPrecmp[row] = new PrecompGroupElement(curve, ypx, ymx, xy2d);
                        }
                    } else {
                        row += 1;
                    }
                } else {
                    break;
                }
            }
        } catch (@NotNull final IOException e) {
            e.printStackTrace();
        } finally {
            if (null != file) try { file.close(); } catch (@NotNull final IOException e) {}
        }
        return dblPrecmp;
    }
}
