package net.i2p.crypto.eddsa.math;

import org.jetbrains.annotations.NotNull;

public interface FieldElement {
    abstract byte[] toByteArray();

    boolean isNonZero();

    abstract boolean isNegative();

    @NotNull
    FieldElement add(FieldElement element);

    abstract FieldElement addOne();

    @NotNull
    FieldElement subtract(FieldElement fieldElement);

    abstract FieldElement subtractOne();

    FieldElement negate();

    abstract FieldElement divide(FieldElement fieldElement);

    @NotNull
    FieldElement multiply(FieldElement fieldElement);

    @NotNull
    FieldElement square();

    FieldElement squareAndDouble();

    FieldElement invert();

    @NotNull
    FieldElement pow22523();

    @NotNull
    FieldElement cmov(FieldElement fieldElement, int b);

    EdDSAFiniteField getEdDSAFiniteField();
}
