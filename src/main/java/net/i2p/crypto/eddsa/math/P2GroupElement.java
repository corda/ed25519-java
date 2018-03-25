package net.i2p.crypto.eddsa.math;

/**
 * Creates a new group element in P2 representation.
 *
 * @param curve The curve.
 * @param X     The $X$ coordinate.
 * @param Y     The $Y$ coordinate.
 * @param Z     The $Z$ coordinate.
 * @return The group element in P2 representation.
 */

class P2GroupElement extends BaseGroupElement {
    public P2GroupElement(Curve curve, FieldElement x, FieldElement y, FieldElement z) {
        super(curve, Representation.P2, x, y, z, null, false);
    }
}
