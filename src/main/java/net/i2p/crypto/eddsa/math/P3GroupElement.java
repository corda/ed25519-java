package net.i2p.crypto.eddsa.math;

import net.i2p.crypto.eddsa.Utils;
import org.jetbrains.annotations.NotNull;

/**
 * Creates a new group element in P3 representation.
 *
 * @param curve                The curve.
 * @param X                    The $X$ coordinate.
 * @param Y                    The $Y$ coordinate.
 * @param Z                    The $Z$ coordinate.
 * @param T                    The $T$ coordinate.
 * @param precomputeDoubleOnly set to null.
 * @return The group element in P3 representation.
 */
public class P3GroupElement extends BaseGroupElement {
    public P3GroupElement(Curve curve, FieldElement x, FieldElement y, FieldElement z, FieldElement t,boolean precompute ) {
        super(curve, Representation.P3, x, y, z, t, precompute);
    }

    /**
     * Creates a group element for a curve from a given encoded point.
     * <p>
     * A point $(x,y)$ is encoded by storing $y$ in bit 0 to bit 254 and the sign of $x$ in bit 255.
     * $x$ is recovered in the following way:
     * </p><ul>
     * <li>$x = sign(x) * \sqrt{(y^2 - 1) / (d * y^2 + 1)} = sign(x) * \sqrt{u / v}$ with $u = y^2 - 1$ and $v = d * y^2 + 1$.
     * <li>Setting $β = (u * v^3) * (u * v^7)^{((q - 5) / 8)}$ one has $β^2 = \pm(u / v)$.
     * <li>If $v * β = -u$ multiply $β$ with $i=\sqrt{-1}$.
     * <li>Set $x := β$.
     * <li>If $sign(x) \ne$ bit 255 of $s$ then negate $x$.
     * </ul>
     *
     * @param curve The curve.
     * @param s     The encoded point.
     */
    public P3GroupElement(@NotNull final Curve curve, @NotNull final byte[] s) {
        /**
         * Creates a group element for a curve from a given encoded point.
         * <p>
         * A point $(x,y)$ is encoded by storing $y$ in bit 0 to bit 254 and the sign of $x$ in bit 255.
         * $x$ is recovered in the following way:
         * </p><ul>
         * <li>$x = sign(x) * \sqrt{(y^2 - 1) / (d * y^2 + 1)} = sign(x) * \sqrt{u / v}$ with $u = y^2 - 1$ and $v = d * y^2 + 1$.
         * <li>Setting $β = (u * v^3) * (u * v^7)^{((q - 5) / 8)}$ one has $β^2 = \pm(u / v)$.
         * <li>If $v * β = -u$ multiply $β$ with $i=\sqrt{-1}$.
         * <li>Set $x := β$.
         * <li>If $sign(x) \ne$ bit 255 of $s$ then negate $x$.
         * </ul>
         *
         * @param curve The curve.
         * @param s     The encoded point.
         */this(curve, s, false);
    }
    /**
     * Creates a group element for a curve from a given encoded point.
     * <p>
     * A point $(x,y)$ is encoded by storing $y$ in bit 0 to bit 254 and the sign of $x$ in bit 255.
     * $x$ is recovered in the following way:
     * </p><ul>
     * <li>$x = sign(x) * \sqrt{(y^2 - 1) / (d * y^2 + 1)} = sign(x) * \sqrt{u / v}$ with $u = y^2 - 1$ and $v = d * y^2 + 1$.
     * <li>Setting $β = (u * v^3) * (u * v^7)^{((q - 5) / 8)}$ one has $β^2 = \pm(u / v)$.
     * <li>If $v * β = -u$ multiply $β$ with $i=\sqrt{-1}$.
     * <li>Set $x := β$.
     * <li>If $sign(x) \ne$ bit 255 of $s$ then negate $x$.
     * </ul>
     *
     * @param curve                     The curve.
     * @param s                         The encoded point.
     * @param precomputeSingleAndDouble If true, populate both precmp and dblPrecmp, else set both to null.
     */
    // TODO
    /*protected GroupElement(*/
    public P3GroupElement(//Curve curve, Representation p3, FieldElement x, FieldElement y, FieldElement z, FieldElement t, boolean b) {



                          final Curve curve, @NotNull final byte[] s, final boolean precomputeSingleAndDouble) {
        super();
        FieldElement x;
        final FieldElement y;
        @NotNull final FieldElement yy;
        final FieldElement u;
        final FieldElement v;
        @NotNull final FieldElement v3;
        @NotNull final FieldElement vxx;
        FieldElement check;
        y = curve.getEdDSAFiniteField().fromByteArray(s);
        yy = y.square();

        // u = y^2-1
        u = yy.subtractOne();

        // v = dy^2+1
        v = yy.multiply(curve.getFieldElementD()).addOne();

        // v3 = v^3
        v3 = v.square().multiply(v);

        // x = (v3^2)vu, aka x = uv^7
        x = v3.square().multiply(v).multiply(u);

        //  x = (uv^7)^((q-5)/8)
        x = x.pow22523();

        // x = uv^3(uv^7)^((q-5)/8)
        x = v3.multiply(u).multiply(x);

        vxx = x.square().multiply(v);
        check = vxx.subtract(u);            // vx^2-u
        if (check.isNonZero()) {
            check = vxx.add(u);             // vx^2+u

            assert !check.isNonZero() : "not a valid GroupElement";
            x = x.multiply(curve.getFieldElementI());
        }

        if ((x.isNegative() ? 1 : 0) != Utils.bit(s, curve.getEdDSAFiniteField().getb() - 1)) {
            x = x.negate();
        }

        this.curve = curve;
        this.repr = Representation.P3;
        this.X = x;
        this.Y = y;
        this.Z = curve.getEdDSAFiniteField().ONE;
        this.T = this.getX().multiply(this.getY());
        if (precomputeSingleAndDouble) {
            precmp = precomputeSingle();
            dblPrecmp = precomputeDouble();
        } else {
            precmp = null;
            dblPrecmp = null;
        }
    }

    public P3GroupElement(Curve curve2, FieldElement x1, FieldElement y1, FieldElement z1, FieldElement t1) {
        this(curve2, x1, y1, z1, t1, false);
    }
}
