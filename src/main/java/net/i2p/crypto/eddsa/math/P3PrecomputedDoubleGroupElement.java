package net.i2p.crypto.eddsa.math;
public
class P3PrecomputedDoubleGroupElement extends P3PreGroupElement {
    public P3PrecomputedDoubleGroupElement(Curve c, FieldElement zero, FieldElement one) {
        super(c, zero, one, one, zero);
    }
}
