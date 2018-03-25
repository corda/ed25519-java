package net.i2p.crypto.eddsa.math;

/**
 * Creates a new group element in CACHED representation.
 *
 * @param curve The curve.
 * @param YpX   The $Y + X$ value.
 * @param YmX   The $Y - X$ value.
 * @param Z     The $Z$ coordinate.
 * @param T2d   The $2 * d * T$ value.
 * @return The group element in CACHED representation.
 */

class CachedGroupElement extends BaseGroupElement {
    public CachedGroupElement(Curve curve, FieldElement ypX, FieldElement ymX, FieldElement z, FieldElement t2d) {
        super(curve, Representation.CACHED, ypX, ymX, z, t2d, false);
    }
}
