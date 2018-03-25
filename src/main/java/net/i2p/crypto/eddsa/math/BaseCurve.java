/**
 * EdDSA-Java by str4d
 * <p>
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 * <p>
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 */
package net.i2p.crypto.eddsa.math;

import org.jetbrains.annotations.NotNull;

import java.util.EnumMap;
import java.util.concurrent.Callable;

/**
 * A twisted Edwards curve.
 * Points on the curve satisfy $-x^2 + y^2 = 1 + d x^2y^2$
 *
 * @author str4d
 */
@SuppressWarnings("ThisEscapedInObjectConstruction")
public class BaseCurve implements Curve {
    @NotNull
    private final EdDSAFiniteField edDSAFiniteField;
    private final FieldElement fieldElementD;
    private final FieldElement fieldElementD2;
    private final FieldElement fieldElementI;
    @NotNull
    private final  EnumMap<Representation, Callable<? extends GroupElement>> source = new EnumMap<Representation, Callable<? extends GroupElement>>(Representation.class);
    private final EnumMap<Representation, GroupElement> facade = new EnumMap<>(Representation.class);

    public BaseCurve(@NotNull EdDSAFiniteField edDSAFiniteField, FieldElement fieldElementD, FieldElement fieldElementD2, FieldElement fieldElementI) {
        this.edDSAFiniteField = edDSAFiniteField;
        this.fieldElementD = fieldElementD;
        this.fieldElementD2 = fieldElementD2;
        this.fieldElementI = fieldElementI;
    }

    private void initSource() {
        FieldElement zero = getEdDSAFiniteField().ZERO;
        FieldElement one = getEdDSAFiniteField().ONE;
        source.put(Representation.P2, () -> new P2GroupElement(BaseCurve.this, zero, one, one));
        source.put(Representation.P3, () -> new P3GroupElement(BaseCurve.this, zero, one, one, zero));
        source.put(Representation.P3PrecomputedDouble, () -> new P3PrecomputedDoubleGroupElement(BaseCurve.this, zero, one));
        source.put(Representation.PRECOMP, () -> new PrecompGroupElement(BaseCurve.this, one, one, zero));
    }


    @NotNull
    @Override
    public GroupElement createPoint(byte[] P, boolean precompute) {assert precompute;
        return new P3PreGroupElement(this, P );
    }

    @Override
    public int hashCode() {
        return getEdDSAFiniteField().hashCode() ^
                getFieldElementD().hashCode() ^
                getFieldElementI().hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof Curve))
            return false;
        @NotNull Curve c = (Curve) o;
        return getEdDSAFiniteField().equals(c.getEdDSAFiniteField()) &&
                getFieldElementD().equals(c.getFieldElementD()) &&
                getFieldElementI().equals(c.getFieldElementI());
    }

    @NotNull
    @Override
    public EdDSAFiniteField getEdDSAFiniteField() {
        return edDSAFiniteField;
    }

    @Override
    public FieldElement getFieldElementD() {
        return fieldElementD;
    }

    @Override
    public FieldElement getFieldElementD2() {
        return fieldElementD2;
    }

    @Override
    public FieldElement getFieldElementI() {
        return fieldElementI;
    }

    @Override
    public GroupElement getZeroP2() throws RuntimeException {
        return get (Representation.P2 );

    }

    @Override
    public GroupElement getZeroP3() {
        return get (Representation.P3 );

    }

    @Override
    public GroupElement getZeroP3PrecomputedDouble() {
        return get (Representation.P3PrecomputedDouble );
    }

    @Override
    public GroupElement getZeroPrecomp() {
        return get (Representation.PRECOMP );

    }

    public GroupElement get(Representation Representation) {
        if(source.isEmpty())initSource();
        return getFacade().computeIfAbsent(Representation, representation -> {
            try {
                return getSource().get(Representation).call();
            } catch (Exception e) {
                throw new Error(e);
            }
        });
    }

    @NotNull
    public EnumMap<Representation, Callable<? extends GroupElement>> getSource() {
        return source;
    }

    public EnumMap<Representation, GroupElement> getFacade() {
        return facade;
    }
}
