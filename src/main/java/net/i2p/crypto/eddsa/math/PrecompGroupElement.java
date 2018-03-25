package net.i2p.crypto.eddsa.math;

/**
 * Creates a new group element in PRECOMP representation.
 *
 * @param curve The curve.
 * @param ypx   The $y + x$ value.
 * @param ymx   The $y - x$ value.
 * @param xy2d  The $2 * d * x * y$ value.
 * @return The group element in PRECOMP representation.
 */

class PrecompGroupElement extends BaseGroupElement {
    public PrecompGroupElement(Curve curve, FieldElement ypx, FieldElement ymx, FieldElement xy2d) {
        super(curve, Representation.PRECOMP, ypx, ymx, xy2d, null, false);
    }
}
