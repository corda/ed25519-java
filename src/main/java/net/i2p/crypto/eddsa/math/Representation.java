package net.i2p.crypto.eddsa.math;

import org.jetbrains.annotations.NotNull;

/**
 * Available representations for a group element.
 * <ul>
 * <li>P2: Projective representation $(X:Y:Z)$ satisfying $x=X/Z, y=Y/Z$.
 * <li>P3: Extended projective representation $(X:Y:Z:T)$ satisfying $x=X/Z, y=Y/Z, XY=ZT$.
 * <li>P3PrecomputedDouble: P3 but with dblPrecmp populated.
 * <li>P1P1: Completed representation $((X:Z), (Y:T))$ satisfying $x=X/Z, y=Y/T$.
 * <li>PRECOMP: Precomputed representation $(y+x, y-x, 2dxy)$.
 * <li>CACHED: Cached representation $(Y+X, Y-X, Z, 2dT)$
 * </ul>
 */
public enum Representation {
    /**
     * Projective ($P^2$): $(X:Y:Z)$ satisfying $x=X/Z, y=Y/Z$
     */
    P2 {
        @NotNull
        public GroupElement toRep(@NotNull GroupElement groupElement) {
            switch (groupElement.getRepr()) {
                case P2:
                    return new P2GroupElement(groupElement.getCurve(), groupElement.getX(), groupElement.getY(), groupElement.getZ());
                case P3:
                    return new P2GroupElement(groupElement.getCurve(), groupElement.getX(), groupElement.getY(), groupElement.getZ());
                case P1P1:
                    return new P2GroupElement(groupElement.getCurve(), groupElement.getX().multiply(groupElement.getT()), groupElement.getY().multiply(groupElement.getZ()), groupElement.getZ().multiply(groupElement.getT()));
                case PRECOMP:
                    throw new IllegalArgumentException();
                case CACHED:
                    throw new IllegalArgumentException();
                default:
                    throw new UnsupportedOperationException();
            }
        }
    },
    /**
     * Extended ($P^3$): $(X:Y:Z:T)$ satisfying $x=X/Z, y=Y/Z, XY=ZT$
     */
    P3 {
        @NotNull
        public GroupElement toRep(@NotNull GroupElement groupElement) {
            switch (groupElement.getRepr()) {
                case P2:
                    throw new IllegalArgumentException();
                case P3:
                    final Curve curve1 = groupElement.getCurve();
                    final FieldElement x = groupElement.getX();
                    final FieldElement y = groupElement.getY();
                    final FieldElement z = groupElement.getZ();
                    final FieldElement t = groupElement.getT();
                    /**
                     * Creates a new group element in P3 representation.
                     *
                     * @param curve The curve.
                     * @param X The $X$ coordinate.
                     * @param Y The $Y$ coordinate.
                     * @param Z The $Z$ coordinate.
                     * @param T The $T$ coordinate.
                     * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
                     * @return The group element in P3 representation.
                     */
                    return false ? new P3PreGroupElement(curve1, x, y, z, t) : new P3GroupElement(curve1, x, y, z, t);
                case P1P1:

                    final Curve curve2 = groupElement.getCurve();
                    @NotNull final FieldElement x1 = groupElement.getX().multiply(groupElement.getT());
                    @NotNull final FieldElement y1 = groupElement.getY().multiply(groupElement.getZ());
                    @NotNull final FieldElement z1 = groupElement.getZ().multiply(groupElement.getT());
                    @NotNull final FieldElement t1 = groupElement.getX().multiply(groupElement.getY());
                    /**
                     * Creates a new group element in P3 representation.
                     *
                     * @param curve The curve.
                     * @param X The $X$ coordinate.
                     * @param Y The $Y$ coordinate.
                     * @param Z The $Z$ coordinate.
                     * @param T The $T$ coordinate.
                     * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
                     * @return The group element in P3 representation.
                     */
                    return new P3GroupElement(curve2, x1, y1, z1, t1);
                case PRECOMP:
                    throw new IllegalArgumentException();
                case CACHED:
                    throw new IllegalArgumentException();
                default:
                    throw new UnsupportedOperationException();
            }
        }
    },
    /**
     * P3 but also populate dblPrecmp
     */
    P3PrecomputedDouble {
        @NotNull
        public GroupElement toRep(@NotNull GroupElement groupElement) {
            switch (groupElement.getRepr()) {
                case P2:
                    throw new IllegalArgumentException();
                case P3:
                    throw new IllegalArgumentException();
                case P1P1:
                    final Curve curve1 = groupElement.getCurve();
                    @NotNull final FieldElement x = groupElement.getX().multiply(groupElement.getT());
                    @NotNull final FieldElement y = groupElement.getY().multiply(groupElement.getZ());
                    @NotNull final FieldElement z = groupElement.getZ().multiply(groupElement.getT());
                    @NotNull final FieldElement t = groupElement.getX().multiply(groupElement.getY());
                    /**
                     * Creates a new group element in P3 representation.
                     *
                     * @param curve The curve.
                     * @param X The $X$ coordinate.
                     * @param Y The $Y$ coordinate.
                     * @param Z The $Z$ coordinate.
                     * @param T The $T$ coordinate.
                     * @param precomputeDoubleOnly If true, populate dblPrecmp, else set to null.
                     * @return The group element in P3 representation.
                     */
                    return new P3PreGroupElement(curve1, x, y, z, t);
                case PRECOMP:
                    throw new IllegalArgumentException();
                case CACHED:
                    throw new IllegalArgumentException();
                default:
                    throw new UnsupportedOperationException();
            }
        }
    },
    /**
     * Completed ($P \times P$): $((X:Z),(Y:T))$ satisfying $x=X/Z, y=Y/T$
     */
    P1P1 {
        @NotNull
        public GroupElement toRep(@NotNull GroupElement groupElement) {
            if (groupElement.getRepr() == Representation.P1P1) {

                /**
                 * Creates a new group element in P1P1 representation.
                 *
                 * @param curve The curve.
                 * @param X The $X$ coordinate.
                 * @param Y The $Y$ coordinate.
                 * @param Z The $Z$ coordinate.
                 * @param T The $T$ coordinate.
                 * @return The group element in P1P1 representation.
                 */
                return new P1pGroupElement(groupElement.getCurve(), groupElement.getX(), groupElement.getY(), groupElement.getZ(), groupElement.getT());
            }
            if (groupElement.getRepr() == Representation.P2 || groupElement.getRepr() == Representation.P3 || groupElement.getRepr() == Representation.PRECOMP || groupElement.getRepr() == Representation.CACHED)
                throw new IllegalArgumentException();
            throw new UnsupportedOperationException();
        }
    },
    /**
     * Precomputed (Duif): $(y+x,y-x,2dxy)$
     */
    PRECOMP {
        @NotNull
        public GroupElement toRep(@NotNull GroupElement groupElement) {
            if (groupElement.getRepr() == Representation.PRECOMP) {
                return
                        /**
                         * Creates a new group element in PRECOMP representation.
                         *
                         * @param curve The curve.
                         * @param ypx The $y + x$ value.
                         * @param ymx The $y - x$ value.
                         * @param xy2d The $2 * d * x * y$ value.
                         * @return The group element in PRECOMP representation.
                         */new PrecompGroupElement(groupElement.getCurve(), groupElement.getX(), groupElement.getY(), groupElement.getZ());
            }
            if (groupElement.getRepr() == Representation.P2 || groupElement.getRepr() == Representation.P3 || groupElement.getRepr() == Representation.P1P1 || groupElement.getRepr() == Representation.CACHED)
                throw new IllegalArgumentException();
            throw new UnsupportedOperationException();
        }
    },
    /**
     * Cached: $(Y+X,Y-X,Z,2dT)$
     */
    CACHED {
        @NotNull
        public GroupElement toRep(@NotNull GroupElement groupElement) {
            switch (groupElement.getRepr()) {
                case P3:
                    return new CachedGroupElement(groupElement.getCurve(), groupElement.getY().add(groupElement.getX()), groupElement.getY().subtract(groupElement.getX()), groupElement.getZ(), groupElement.getT().multiply(groupElement.getCurve().getFieldElementD2()));
                case P1P1:
                case PRECOMP:
                case P2:
                    throw new IllegalArgumentException();
                case CACHED:
                    return new CachedGroupElement(groupElement.getCurve(), groupElement.getX(), groupElement.getY(), groupElement.getZ(), groupElement.getT());
                default:
                    throw new UnsupportedOperationException();
            }
        }
    };

    /**
     * Convert a GroupElement from one Representation to another.
     * TODO-CR: Add additional conversion?
     * $r = p$
     * <p>
     * Supported conversions:
     * <p><ul>
     * <li>P3 $\rightarrow$ P2
     * <li>P3 $\rightarrow$ CACHED (1 multiply, 1 add, 1 subtract)
     * <li>P1P1 $\rightarrow$ P2 (3 multiply)
     * <li>P1P1 $\rightarrow$ P3 (4 multiply)
     *
     * @param groupElement@return A new group element in the given representation.
     */
   @NotNull
   abstract public GroupElement toRep(GroupElement groupElement);
}
