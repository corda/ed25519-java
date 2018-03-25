package net.i2p.crypto.eddsa.math;

import org.jetbrains.annotations.NotNull;

/**
 * Creates a new group element in P3 representation.
 *
 * @param curve                The curve.
 * @param X                    The $X$ coordinate.
 * @param Y                    The $Y$ coordinate.
 * @param Z                    The $Z$ coordinate.
 * @param T                    The $T$ coordinate.
 * @param precomputeDoubleOnly populate dblPrecmp
 * @return The group element in P3 representation.
 */
public
class P3PreGroupElement extends P3GroupElement {
    public P3PreGroupElement(Curve curve, FieldElement x, FieldElement y, FieldElement z, FieldElement t) {
        super(curve,  x, y, z, t, true);
    }

    public P3PreGroupElement(@NotNull Curve curve, @NotNull byte[] bytes) {
        super(curve, bytes,true);
    }
}
