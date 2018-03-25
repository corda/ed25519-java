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

import net.i2p.crypto.eddsa.Utils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;

/**
 * A point $(x,y)$ on an EdDSA curve.
 * <p>
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 * <p>
 * Literature:<br>
 * [1] Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang : High-speed high-security signatures<br>
 * [2] Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, Ed Dawson: Twisted Edwards Curves Revisited<br>
 * [3] Daniel J. Bernsteina, Tanja Lange: A complete set of addition laws for incomplete Edwards curves<br>
 * [4] Daniel J. Bernstein, Peter Birkner, Marc Joye, Tanja Lange and Christiane Peters: Twisted Edwards Curves<br>
 * [5] Christiane Pascale Peters: Curves, Codes, and Cryptography (PhD thesis)<br>
 * [6] Daniel J. Bernstein, Peter Birkner, Tanja Lange and Christiane Peters: Optimizing double-base elliptic-curve single-scalar multiplication<br>
 *
 * @author str4d
 */
public class BaseGroupElement implements GroupElement {

    public Curve curve;
    public Representation repr;
    public FieldElement X;
    public FieldElement Y;
    public FieldElement Z;
    public FieldElement T;
    @Nullable
    public GroupElement[][] precmp;
    @Nullable
    public GroupElement[] dblPrecmp;

    /**
     * Creates a group element for a curve.
     *
     * @param curve            The curve.
     * @param repr             The representation used to represent the group element.
     * @param X                The $X$ coordinate.
     * @param Y                The $Y$ coordinate.
     * @param Z                The $Z$ coordinate.
     * @param T                The $T$ coordinate.
     * @param precomputeDouble If true, populate dblPrecmp, else set to null.
     */
    protected BaseGroupElement(
            final Curve curve,
            final Representation repr,
            final FieldElement X,
            final FieldElement Y,
            final FieldElement Z,
            final FieldElement T,
            final boolean precomputeDouble) {
        this.curve = curve;
        this.repr = repr;
        this.X = X;
        this.Y = Y;
        this.Z = Z;
        this.T = T;
        this.precmp = null;
        this.dblPrecmp = precomputeDouble ? precomputeDouble() : null;
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
    protected BaseGroupElement(final Curve curve, @NotNull final byte[] s, final boolean precomputeSingleAndDouble) {
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

    public BaseGroupElement() {

    }

    /**
     * Variable is package public only so that tests run.
     */
    @Override
    public Representation getRepr() {
        return repr;
    }

    /**
     * Variable is package public only so that tests run.
     */
    @Override
    public FieldElement getX() {
        return X;
    }

    /**
     * Variable is package public only so that tests run.
     */
    @Override
    public FieldElement getY() {
        return Y;
    }

    /**
     * Variable is package public only so that tests run.
     */
    @Override
    public FieldElement getZ() {
        return Z;
    }

    /**
     * Variable is package public only so that tests run.
     */
    @Override
    public FieldElement getT() {
        return T;
    }

    /**
     * Precomputed table for {@link #scalarMultiply(byte[])},
     * filled if necessary.
     * <p>
     * Variable is package public only so that tests run.
     */
    @Nullable
    @Override
    public GroupElement[][] getPrecmp() {
        return precmp;
    }

    /**
     * Variable is package public only so that tests run.
     */

    /**
     * Precomputed table for {@link #doubleScalarMultiplyVariableTime(GroupElement, byte[], byte[])},
     * filled if necessary.
     * <p>
     * Variable is package public only so that tests run.
     */
    @Nullable
    @Override
    public GroupElement[] getDblPrecmp() {
        return dblPrecmp;
    }

    /**
     * Gets the curve of the group element.
     *
     * @return The curve.
     */
    @Override
    public Curve getCurve() {
        return this.curve;
    }

    /**
     * Gets the representation of the group element.
     *
     * @return The representation.
     */
    @Override
    public Representation getRepresentation() {
        return this.getRepr();
    }

    /**
     * Converts the group element to an encoded point on the curve.
     *
     * @return The encoded point as byte array.
     */
    @Override
    public byte[] toByteArray() {
        switch (this.getRepr()) {
            case P2:
            case P3:
                final FieldElement recip = getZ().invert();
                @NotNull final FieldElement x = getX().multiply(recip);
                @NotNull final FieldElement y = getY().multiply(recip);
                final byte[] s = y.toByteArray();
                s[s.length - 1] |= (x.isNegative() ? (byte) 0x80 : (byte) 0);
                return s;
            default:
                return Representation.P2.toRep(this).toByteArray();
        }
    }

    /**
     * Precomputes table for {@link #scalarMultiply(byte[])}.
     */
    @NotNull
    @Override
    public GroupElement[][] precomputeSingle() {
        // Precomputation for single scalar multiplication.
        @NotNull final GroupElement[][] precmp = new GroupElement[32][8];
        // TODO-CR BR: check that this == base point when the method is called.
        @NotNull GroupElement Bi = this;
        for (int i = 0; 32 > i; i++) {
            @NotNull GroupElement Bij = Bi;
            for (int j = 0; 8 > j; j++) {
                final FieldElement recip = Bij.getZ().invert();
                @NotNull final FieldElement x = Bij.getX().multiply(recip);
                @NotNull final FieldElement y = Bij.getY().multiply(recip);
                precmp[i][j] = new PrecompGroupElement(this.getCurve(), y.add(x), y.subtract(x), x.multiply(y).multiply(this.getCurve().getFieldElementD2()));
                Bij = Representation.P3.toRep(Bij.add(Representation.CACHED.toRep(Bi)));
            }
            // Only every second summand is precomputed (16^2 = 256)
            for (int k = 0; 8 > k; k++) {
                Bi = Representation.P3.toRep(Bi.add(Representation.CACHED.toRep(Bi)));
            }
        }
        return precmp;
    }

    /**
     * Precomputes table for {@link #doubleScalarMultiplyVariableTime(GroupElement, byte[], byte[])}.
     */
    @NotNull
    @Override
    public GroupElement[] precomputeDouble() {
        // Precomputation for double scalar multiplication.
        // P,3P,5P,7P,9P,11P,13P,15P
        @NotNull final GroupElement[] dblPrecmp = new GroupElement[8];
        @NotNull GroupElement Bi = this;
        for (int i = 0; 8 > i; i++) {
            final FieldElement recip = Bi.getZ().invert();
            @NotNull final FieldElement x = Bi.getX().multiply(recip);
            @NotNull final FieldElement y = Bi.getY().multiply(recip);
            dblPrecmp[i] = new PrecompGroupElement(this.getCurve(), y.add(x), y.subtract(x), x.multiply(y).multiply(this.getCurve().getFieldElementD2()));
            // Bi = edwards(B,edwards(B,Bi))
            Bi = Representation.P3.toRep(this.add(Representation.CACHED.toRep(Representation.P3.toRep(this.add(Representation.CACHED.toRep(Bi))))));
        }
        return dblPrecmp;
    }

    /**
     * Doubles a given group element $p$ in $P^2$ or $P^3$ representation and returns the result in $P \times P$ representation.
     * $r = 2 * p$ where $p = (X : Y : Z)$ or $p = (X : Y : Z : T)$
     * <p>
     * $r$ in $P \times P$ representation:
     * <p>
     * $r = ((X' : Z'), (Y' : T'))$ where
     * </p><ul>
     * <li>$X' = (X + Y)^2 - (Y^2 + X^2)$
     * <li>$Y' = Y^2 + X^2$
     * <li>$Z' = y^2 - X^2$
     * <li>$T' = 2 * Z^2 - (y^2 - X^2)$
     * </ul><p>
     * $r$ converted from $P \times P$ to $P^2$ representation:
     * <p>
     * $r = (X'' : Y'' : Z'')$ where
     * </p><ul>
     * <li>$X'' = X' * Z' = ((X + Y)^2 - Y^2 - X^2) * (2 * Z^2 - (y^2 - X^2))$
     * <li>$Y'' = Y' * T' = (Y^2 + X^2) * (2 * Z^2 - (y^2 - X^2))$
     * <li>$Z'' = Z' * T' = (y^2 - X^2) * (2 * Z^2 - (y^2 - X^2))$
     * </ul><p>
     * Formula for the $P^2$ representation is in agreement with the formula given in [4] page 12 (with $a = -1$)
     * up to a common factor -1 which does not matter:
     * <p>
     * $$
     * B = (X + Y)^2; C = X^2; D = Y^2; E = -C = -X^2; F := E + D = Y^2 - X^2; H = Z^2; J = F − 2 * H; \\
     * X3 = (B − C − D) · J = X' * (-T'); \\
     * Y3 = F · (E − D) = Z' * (-Y'); \\
     * Z3 = F · J = Z' * (-T').
     * $$
     *
     * @return The P1P1 representation
     */
    @NotNull
    @Override
    public GroupElement dbl() {
        switch (this.getRepr()) {
            case P2:
            case P3: // Ignore T for P3 representation
                @NotNull final FieldElement XX;
                @NotNull final FieldElement YY;
                final FieldElement B;
                @NotNull final FieldElement A;
                @NotNull final FieldElement AA;
                @NotNull final FieldElement Yn;
                @NotNull final FieldElement Zn;
                XX = this.getX().square();
                YY = this.getY().square();
                B = this.getZ().squareAndDouble();
                A = this.getX().add(this.getY());
                AA = A.square();
                Yn = YY.add(XX);
                Zn = YY.subtract(XX);

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
                return new P1pGroupElement(this.getCurve(), AA.subtract(Yn), Yn, Zn, B.subtract(Zn));
            default:
                throw new UnsupportedOperationException();
        }
    }

    /**
     * GroupElement addition using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * <p>
     * this must be in $P^3$ representation and $q$ in PRECOMP representation.
     * $r = p + q$ where $p = this = (X1 : Y1 : Z1 : T1), q = (q.X, q.Y, q.Z) = (Y2/Z2 + X2/Z2, Y2/Z2 - X2/Z2, 2 * d * X2/Z2 * Y2/Z2)$
     * <p>
     * $r$ in $P \times P$ representation:
     * <p>
     * $r = ((X' : Z'), (Y' : T'))$ where
     * <p><ul>
     * <li>$X' = (Y1 + X1) * q.X - (Y1 - X1) * q.Y = ((Y1 + X1) * (Y2 + X2) - (Y1 - X1) * (Y2 - X2)) * 1/Z2$
     * <li>$Y' = (Y1 + X1) * q.X + (Y1 - X1) * q.Y = ((Y1 + X1) * (Y2 + X2) + (Y1 - X1) * (Y2 - X2)) * 1/Z2$
     * <li>$Z' = 2 * Z1 + T1 * q.Z = 2 * Z1 + T1 * 2 * d * X2 * Y2 * 1/Z2^2 = (2 * Z1 * Z2 + 2 * d * T1 * T2) * 1/Z2$
     * <li>$T' = 2 * Z1 - T1 * q.Z = 2 * Z1 - T1 * 2 * d * X2 * Y2 * 1/Z2^2 = (2 * Z1 * Z2 - 2 * d * T1 * T2) * 1/Z2$
     * </ul><p>
     * Setting $A = (Y1 - X1) * (Y2 - X2), B = (Y1 + X1) * (Y2 + X2), C = 2 * d * T1 * T2, D = 2 * Z1 * Z2$ we get
     * <p><ul>
     * <li>$X' = (B - A) * 1/Z2$
     * <li>$Y' = (B + A) * 1/Z2$
     * <li>$Z' = (D + C) * 1/Z2$
     * <li>$T' = (D - C) * 1/Z2$
     * </ul><p>
     * $r$ converted from $P \times P$ to $P^2$ representation:
     * <p>
     * $r = (X'' : Y'' : Z'' : T'')$ where
     * <p><ul>
     * <li>$X'' = X' * Z' = (B - A) * (D + C) * 1/Z2^2$
     * <li>$Y'' = Y' * T' = (B + A) * (D - C) * 1/Z2^2$
     * <li>$Z'' = Z' * T' = (D + C) * (D - C) * 1/Z2^2$
     * <li>$T'' = X' * Y' = (B - A) * (B + A) * 1/Z2^2$
     * </ul><p>
     * TODO-CR BR: Formula for the $P^2$ representation is not in agreement with the formula given in [2] page 6<br>
     * TODO-CR BR: (the common factor $1/Z2^2$ does not matter):<br>
     * $$
     * E = B - A, F = D - C, G = D + C, H = B + A \\
     * X3 = E * F = (B - A) * (D - C); \\
     * Y3 = G * H = (D + C) * (B + A); \\
     * Z3 = F * G = (D - C) * (D + C); \\
     * T3 = E * H = (B - A) * (B + A);
     * $$
     *
     * @param q the PRECOMP representation of the GroupElement to add.
     * @return the P1P1 representation of the result.
     */
    @NotNull
    @Override
    public GroupElement madd(@NotNull final GroupElement q) {
        assert Representation.P3 == this.getRepr();
        assert Representation.PRECOMP == q.getRepr();

        @NotNull final FieldElement YpX;
        @NotNull final FieldElement YmX;
        @NotNull final FieldElement A;
        @NotNull final FieldElement B;
        @NotNull final FieldElement C;
        @NotNull final FieldElement D;
        YpX = this.getY().add(this.getX());
        YmX = this.getY().subtract(this.getX());
        A = YpX.multiply(q.getX()); // q->y+x
        B = YmX.multiply(q.getY()); // q->y-x
        C = q.getZ().multiply(this.getT()); // q->2dxy
        D = this.getZ().add(this.getZ());

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
        return new P1pGroupElement(this.getCurve(), A.subtract(B), A.add(B), D.add(C), D.subtract(C));
    }

    /**
     * GroupElement subtraction using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * <p>
     * this must be in $P^3$ representation and $q$ in PRECOMP representation.
     * $r = p - q$ where $p = this = (X1 : Y1 : Z1 : T1), q = (q.X, q.Y, q.Z) = (Y2/Z2 + X2/Z2, Y2/Z2 - X2/Z2, 2 * d * X2/Z2 * Y2/Z2)$
     * <p>
     * Negating $q$ means negating the value of $X2$ and $T2$ (the latter is irrelevant here).
     * The formula is in accordance to {@link #madd the above addition}.
     *
     * @param q the PRECOMP representation of the GroupElement to subtract.
     * @return the P1P1 representation of the result.
     */
    @NotNull
    @Override
    public GroupElement msub(@NotNull final GroupElement q) {
        assert Representation.P3 == this.getRepr();
        assert Representation.PRECOMP == q.getRepr();

        @NotNull final FieldElement YpX;
        @NotNull final FieldElement YmX;
        @NotNull final FieldElement A;
        @NotNull final FieldElement B;
        @NotNull final FieldElement C;
        @NotNull final FieldElement D;
        YpX = this.getY().add(this.getX());
        YmX = this.getY().subtract(this.getX());
        A = YpX.multiply(q.getY()); // q->y-x
        B = YmX.multiply(q.getX()); // q->y+x
        C = q.getZ().multiply(this.getT()); // q->2dxy
        D = this.getZ().add(this.getZ());

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
        return new P1pGroupElement(this.getCurve(), A.subtract(B), A.add(B), D.subtract(C), D.add(C));
    }

    /**
     * GroupElement addition using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * <p>
     * this must be in $P^3$ representation and $q$ in CACHED representation.
     * $r = p + q$ where $p = this = (X1 : Y1 : Z1 : T1), q = (q.X, q.Y, q.Z, q.T) = (Y2 + X2, Y2 - X2, Z2, 2 * d * T2)$
     * <p>
     * $r$ in $P \times P$ representation:
     * </p><ul>
     * <li>$X' = (Y1 + X1) * (Y2 + X2) - (Y1 - X1) * (Y2 - X2)$
     * <li>$Y' = (Y1 + X1) * (Y2 + X2) + (Y1 - X1) * (Y2 - X2)$
     * <li>$Z' = 2 * Z1 * Z2 + 2 * d * T1 * T2$
     * <li>$T' = 2 * Z1 * T2 - 2 * d * T1 * T2$
     * </ul><p>
     * Setting $A = (Y1 - X1) * (Y2 - X2), B = (Y1 + X1) * (Y2 + X2), C = 2 * d * T1 * T2, D = 2 * Z1 * Z2$ we get
     * </p><ul>
     * <li>$X' = (B - A)$
     * <li>$Y' = (B + A)$
     * <li>$Z' = (D + C)$
     * <li>$T' = (D - C)$
     * </ul><p>
     * Same result as in {@link #madd} (up to a common factor which does not matter).
     *
     * @param q the CACHED representation of the GroupElement to add.
     * @return the P1P1 representation of the result.
     */
    @NotNull
    @Override
    public GroupElement add(@NotNull final GroupElement q) {
        assert Representation.P3 == this.getRepr();
        assert Representation.CACHED == q.getRepr();

        @NotNull final FieldElement YpX;
        @NotNull final FieldElement YmX;
        @NotNull final FieldElement A;
        @NotNull final FieldElement B;
        @NotNull final FieldElement C;
        @NotNull final FieldElement ZZ;
        @NotNull final FieldElement D;
        YpX = this.getY().add(this.getX());
        YmX = this.getY().subtract(this.getX());
        A = YpX.multiply(q.getX()); // q->Y+X
        B = YmX.multiply(q.getY()); // q->Y-X
        C = q.getT().multiply(this.getT()); // q->2dT
        ZZ = this.getZ().multiply(q.getZ());
        D = ZZ.add(ZZ);

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
        return new P1pGroupElement(this.getCurve(), A.subtract(B), A.add(B), D.add(C), D.subtract(C));
    }

    /**
     * GroupElement subtraction using the twisted Edwards addition law with
     * extended coordinates (Hisil2008).
     * <p>
     * $r = p - q$
     * <p>
     * Negating $q$ means negating the value of the coordinate $X2$ and $T2$.
     * The formula is in accordance to {@link #add the above addition}.
     *
     * @param q the PRECOMP representation of the GroupElement to subtract.
     * @return the P1P1 representation of the result.
     */
    @NotNull
    @Override
    public GroupElement sub(@NotNull final GroupElement q) {
        assert Representation.P3 == this.getRepr();
        assert Representation.CACHED == q.getRepr();

        @NotNull final FieldElement YpX;
        @NotNull final FieldElement YmX;
        @NotNull final FieldElement A;
        @NotNull final FieldElement B;
        @NotNull final FieldElement C;
        @NotNull final FieldElement ZZ;
        @NotNull final FieldElement D;
        YpX = getY().add(getX());
        YmX = getY().subtract(getX());
        A = YpX.multiply(q.getY()); // q->Y-X
        B = YmX.multiply(q.getX()); // q->Y+X
        C = q.getT().multiply(getT()); // q->2dT
        ZZ = getZ().multiply(q.getZ());
        D = ZZ.add(ZZ);

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
        return new P1pGroupElement(getCurve(), A.subtract(B), A.add(B), D.subtract(C), D.add(C));
    }

    /**
     * Negates this group element by subtracting it from the neutral group element.
     * <p>
     * TODO-CR BR: why not simply negate the coordinates $X$ and $T$?
     *
     * @return The negative of this group element.
     */
    @NotNull
    @Override
    public GroupElement negate() {
        assert Representation.P3 == this.getRepr();
        return Representation.P3PrecomputedDouble.toRep(this.getCurve().get(Representation.P3).sub(Representation.CACHED.toRep(this)));
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.toByteArray());
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj == this)
            return true;
        if (!(obj instanceof GroupElement))
            return false;
        @NotNull GroupElement ge = (GroupElement) obj;
        if (this.getRepr() != ge.getRepr()) {
            try {
                ge = this.getRepr().toRep(ge);
            } catch (@NotNull final RuntimeException e) {
                return false;
            }
        }
        switch (this.getRepr()) {
            case P2:
            case P3:
                // Try easy way first
                if (this.getZ().equals(ge.getZ()))
                    return this.getX().equals(ge.getX()) && this.getY().equals(ge.getY());
                // X1/Z1 = X2/Z2 --> X1*Z2 = X2*Z1
                @NotNull final FieldElement x1 = this.getX().multiply(ge.getZ());
                @NotNull final FieldElement y1 = this.getY().multiply(ge.getZ());
                @NotNull final FieldElement x2 = ge.getX().multiply(this.getZ());
                @NotNull final FieldElement y2 = ge.getY().multiply(this.getZ());
                return x1.equals(x2) && y1.equals(y2);
            case P1P1:
                return Representation.P2.toRep(this).equals(ge);
            case PRECOMP:
                // Compare directly, PRECOMP is derived directly from x and y
                return this.getX().equals(ge.getX()) && this.getY().equals(ge.getY()) && this.getZ().equals(ge.getZ());
            case CACHED:
                // Try easy way first
                if (this.getZ().equals(ge.getZ()))
                    return this.getX().equals(ge.getX()) && this.getY().equals(ge.getY()) && this.getT().equals(ge.getT());
                // (Y+X)/Z = y+x etc.
                @NotNull final FieldElement x3 = this.getX().multiply(ge.getZ());
                @NotNull final FieldElement y3 = this.getY().multiply(ge.getZ());
                @NotNull final FieldElement t3 = this.getT().multiply(ge.getZ());
                @NotNull final FieldElement x4 = ge.getX().multiply(this.getZ());
                @NotNull final FieldElement y4 = ge.getY().multiply(this.getZ());
                @NotNull final FieldElement t4 = ge.getT().multiply(this.getZ());
                return x3.equals(x4) && y3.equals(y4) && t3.equals(t4);
            default:
                return false;
        }
    }

    /**
     * Constant-time conditional move.
     * <p>
     * Replaces this with $u$ if $b == 1$.<br>
     * Replaces this with this if $b == 0$.
     * <p>
     * Method is package public only so that tests run.
     *
     * @param u The group element to return if $b == 1$.
     * @param b in $\{0, 1\}$
     * @return $u$ if $b == 1$; this if $b == 0$. Results undefined if $b$ is not in $\{0, 1\}$.
     */
    @NotNull
    @Override
    public PrecompGroupElement cmov(@NotNull final GroupElement u, final int b) {
        return
                /**
                 * Creates a new group element in PRECOMP representation.
                 *
                 * @param curve The curve.
                 * @param ypx The $y + x$ value.
                 * @param ymx The $y - x$ value.
                 * @param xy2d The $2 * d * x * y$ value.
                 * @return The group element in PRECOMP representation.
                 */new PrecompGroupElement(getCurve(), getX().cmov(u.getX(), b), getY().cmov(u.getY(), b), getZ().cmov(u.getZ(), b));
    }

    /**
     * Look up $16^i r_i B$ in the precomputed table.
     * <p>
     * No secret array indices, no secret branching.
     * Constant time.
     * <p>
     * Must have previously precomputed.
     * <p>
     * Method is package public only so that tests run.
     *
     * @param pos $= i/2$ for $i$ in $\{0, 2, 4,..., 62\}$
     * @param b   $= r_i$
     * @return the GroupElement
     */
    @Override
    public PrecompGroupElement select(final int pos, final int b) {
        // Is r_i negative?
        final int bnegative = Utils.negative(b);
        // |r_i|
        final int babs = b - (((-bnegative) & b) << 1);

        // 16^i |r_i| B
        @NotNull final  GroupElement t = this.getCurve().get(Representation.PRECOMP)
                .cmov(this.getPrecmp()[pos][0], Utils.equal(babs, 1))
                .cmov(this.getPrecmp()[pos][1], Utils.equal(babs, 2))
                .cmov(this.getPrecmp()[pos][2], Utils.equal(babs, 3))
                .cmov(this.getPrecmp()[pos][3], Utils.equal(babs, 4))
                .cmov(this.getPrecmp()[pos][4], Utils.equal(babs, 5))
                .cmov(this.getPrecmp()[pos][5], Utils.equal(babs, 6))
                .cmov(this.getPrecmp()[pos][6], Utils.equal(babs, 7))
                .cmov(this.getPrecmp()[pos][7], Utils.equal(babs, 8));
        // -16^i |r_i| B
        @NotNull final GroupElement tminus = new PrecompGroupElement(getCurve(), t.getY(), t.getX(), t.getZ().negate());
        // 16^i r_i B
        return t.cmov(tminus, bnegative);
    }

    /**
     * $h = a * B$ where $a = a[0]+256*a[1]+\dots+256^{31} a[31]$ and
     * $B$ is this point. If its lookup table has not been precomputed, it
     * will be at the start of the method (and cached for later calls).
     * Constant time.
     * <p>
     * Preconditions: (TODO: Check this applies here)
     * $a[31] \le 127$
     *
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$
     * @return the GroupElement
     */
    @Override
    public GroupElement scalarMultiply(@NotNull final byte[] a) {
        GroupElement t;
        int i;

        @NotNull final byte[] e = GroupElement.toRadix16(a);

        GroupElement h = this.getCurve().get(Representation.P3);
        for (i = 1; 64 > i; i += 2) {
            t = select(i / 2, e[i]);
            h = Representation.P3.toRep(h.madd(t));
        }

        h = Representation.P3.toRep(Representation.P2.toRep(Representation.P2.toRep(Representation.P2.toRep(h.dbl()).dbl()).dbl()).dbl());

        for (i = 0; 64 > i; i += 2) {
            t = select(i / 2, e[i]);
            h = Representation.P3.toRep(h.madd(t));
        }

        return h;
    }

    /**
     * $r = a * A + b * B$ where $a = a[0]+256*a[1]+\dots+256^{31} a[31]$,
     * $b = b[0]+256*b[1]+\dots+256^{31} b[31]$ and $B$ is this point.
     * <p>
     * $A$ must have been previously precomputed.
     *
     * @param A in P3 representation.
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$
     * @param b $= b[0]+256*b[1]+\dots+256^{31} b[31]$
     * @return the GroupElement
     */
    @Override
    public GroupElement doubleScalarMultiplyVariableTime(@NotNull final GroupElement A, final byte[] a, final byte[] b) {
        // TODO-CR BR: A check that this is the base point is needed.
        @NotNull final byte[] aslide = GroupElement.slide(a);
        @NotNull final byte[] bslide = GroupElement.slide(b);

        GroupElement r = this.getCurve().get(Representation.P2);

        int i;
        i = 255;
        while (0 <= i) {
            if (0 != aslide[i] || 0 != bslide[i]) break;
            --i;
        }

        while (0 <= i) {
            GroupElement t = r.dbl();

            if (0 < aslide[i]) {
                t = Representation.P3.toRep(t).madd(A.getDblPrecmp()[aslide[i] / 2]);
            } else if (0 > aslide[i]) {
                t = Representation.P3.toRep(t).msub(A.getDblPrecmp()[(-aslide[i]) / 2]);
            }

            if (0 < bslide[i]) {
                t = Representation.P3.toRep(t).madd(this.getDblPrecmp()[bslide[i] / 2]);
            } else if (0 > bslide[i]) {
                t = Representation.P3.toRep(t).msub(this.getDblPrecmp()[(-bslide[i]) / 2]);
            }

            r = Representation.P2.toRep(t);
            --i;
        }

        return r;
    }

    /**
     * Verify that a point is on its curve.
     *
     * @return true if the point lies on its curve.
     */
    @Override
    public boolean isOnCurve() {
        return isOnCurve(getCurve());
    }

    /**
     * Verify that a point is on the curve.
     *
     * @param curve The curve to check.
     * @return true if the point lies on the curve.
     */
    @Override
    public boolean isOnCurve(@NotNull final Curve curve) {
        switch (getRepr()) {
            case P2:
            case P3:
                final FieldElement recip = getZ().invert();
                @NotNull final FieldElement x = getX().multiply(recip);
                @NotNull final FieldElement y = getY().multiply(recip);
                @NotNull final FieldElement xx = x.square();
                @NotNull final FieldElement yy = y.square();
                @NotNull final FieldElement dxxyy = curve.getFieldElementD().multiply(xx).multiply(yy);
                return curve.getEdDSAFiniteField().ONE.add(dxxyy).add(xx).equals(yy);

            default:
                return Representation.P2.toRep(this).isOnCurve(curve);
        }
    }

    @NotNull
    @Override
    public String toString() {
        return "[GroupElement\nX=" + getX() + "\nY=" + getY() + "\nZ=" + getZ() + "\nT=" + getT() + "\n]";
    }

}
