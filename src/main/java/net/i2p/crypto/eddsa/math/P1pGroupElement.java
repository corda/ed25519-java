package net.i2p.crypto.eddsa.math;

/**
 * Creates a new group element in P1P1 representation.
 *
 * @param curve The curve.
 * @param X     The $X$ coordinate.
 * @param Y     The $Y$ coordinate.
 * @param Z     The $Z$ coordinate.
 * @param T     The $T$ coordinate.
 * @return The group element in P1P1 representation.
 */
class P1pGroupElement extends BaseGroupElement {
    public P1pGroupElement(Curve curve, FieldElement x, FieldElement y, FieldElement z, FieldElement t) {
        super(curve, Representation.P1P1, x, y, z, t, false);
    }
}
