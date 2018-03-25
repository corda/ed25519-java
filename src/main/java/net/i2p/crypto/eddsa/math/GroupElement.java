package net.i2p.crypto.eddsa.math;

import org.jetbrains.annotations.NotNull;

public interface GroupElement {
    /**
     * Calculates a sliding-windows base 2 representation for a given value $a$.
     * To learn more about it see [6] page 8.
     * <p>
     * Output: $r$ which satisfies
     * $a = r0 * 2^0 + r1 * 2^1 + \dots + r255 * 2^{255}$ with $ri$ in $\{-15, -13, -11, -9, -7, -5, -3, -1, 0, 1, 3, 5, 7, 9, 11, 13, 15\}$
     * <p>
     * Method is package public only so that tests run.
     *
     * @param a $= a[0]+256*a[1]+\dots+256^{31} a[31]$.
     * @return The byte array $r$ in the above described form.
     */
    @NotNull
    static byte[] slide(byte[] a) {
        @NotNull final byte[] r = new byte[256];

        // Put each bit of 'a' into a separate byte, 0 or 1
        for (int i = 0; 256 > i; ++i) {
            r[i] = (byte) (1 & (a[i >> 3] >> (i & 7)));
        }

        // Note: r[i] will always be odd.
        for (int i = 0; 256 > i; ++i) {
            if (0 != r[i]) {
                for (int b = 1; 6 >= b && 256 > i + b; ++b) {
                    // Accumulate bits if possible
                    if (0 != r[i + b]) {
                        if (15 >= r[i] + (r[i + b] << b)) {
                            r[i] = (byte) (r[i] + (r[i + b] << b));
                            r[i + b] = (byte) 0;
                        } else if (-15 <= r[i] - (r[i + b] << b)) {
                            r[i] = (byte) (r[i] - (r[i + b] << b));
                            for (int k = i + b; 256 > k; ++k) {
                                if (0 == r[k]) {
                                    r[k] = (byte) 1;
                                    break;
                                }
                                r[k] = (byte) 0;
                            }
                        } else
                            break;
                    }
                }
            }
        }

        return r;
    }

    /**
     * Convert a to radix 16.
     *
     * Method is package public only so that tests run.
     *
     * @param a $= a[0]+256*a[1]+...+256^{31} a[31]$
     * @return 64 bytes, each between -8 and 7
     */
    @NotNull
    static byte[] toRadix16(byte[] a) {
        @NotNull final byte[] e = new byte[64];

        // Radix 16 notation
        e[2 * 0] = (byte) (a[0] & 15);
        e[2 * 0 + 1] = (byte) ((a[0] >> 4) & 15);
        e[2 * 1] = (byte) (a[1] & 15);
        e[2 * 1 + 1] = (byte) ((a[1] >> 4) & 15);
        e[2 * 2] = (byte) (a[2] & 15);
        e[2 * 2 + 1] = (byte) ((a[2] >> 4) & 15);
        e[2 * 3] = (byte) (a[3] & 15);
        e[2 * 3 + 1] = (byte) ((a[3] >> 4) & 15);
        e[2 * 4] = (byte) (a[4] & 15);
        e[2 * 4 + 1] = (byte) ((a[4] >> 4) & 15);
        e[2 * 5] = (byte) (a[5] & 15);
        e[2 * 5 + 1] = (byte) ((a[5] >> 4) & 15);
        e[2 * 6] = (byte) (a[6] & 15);
        e[2 * 6 + 1] = (byte) ((a[6] >> 4) & 15);
        e[2 * 7] = (byte) (a[7] & 15);
        e[2 * 7 + 1] = (byte) ((a[7] >> 4) & 15);
        e[2 * 8] = (byte) (a[8] & 15);
        e[2 * 8 + 1] = (byte) ((a[8] >> 4) & 15);
        e[2 * 9] = (byte) (a[9] & 15);
        e[2 * 9 + 1] = (byte) ((a[9] >> 4) & 15);
        e[2 * 10] = (byte) (a[10] & 15);
        e[2 * 10 + 1] = (byte) ((a[10] >> 4) & 15);
        e[2 * 11] = (byte) (a[11] & 15);
        e[2 * 11 + 1] = (byte) ((a[11] >> 4) & 15);
        e[2 * 12] = (byte) (a[12] & 15);
        e[2 * 12 + 1] = (byte) ((a[12] >> 4) & 15);
        e[2 * 13] = (byte) (a[13] & 15);
        e[2 * 13 + 1] = (byte) ((a[13] >> 4) & 15);
        e[2 * 14] = (byte) (a[14] & 15);
        e[2 * 14 + 1] = (byte) ((a[14] >> 4) & 15);
        e[2 * 15] = (byte) (a[15] & 15);
        e[2 * 15 + 1] = (byte) ((a[15] >> 4) & 15);
        e[2 * 16] = (byte) (a[16] & 15);
        e[2 * 16 + 1] = (byte) ((a[16] >> 4) & 15);
        e[2 * 17] = (byte) (a[17] & 15);
        e[2 * 17 + 1] = (byte) ((a[17] >> 4) & 15);
        e[2 * 18] = (byte) (a[18] & 15);
        e[2 * 18 + 1] = (byte) ((a[18] >> 4) & 15);
        e[2 * 19] = (byte) (a[19] & 15);
        e[2 * 19 + 1] = (byte) ((a[19] >> 4) & 15);
        e[2 * 20] = (byte) (a[20] & 15);
        e[2 * 20 + 1] = (byte) ((a[20] >> 4) & 15);
        e[2 * 21] = (byte) (a[21] & 15);
        e[2 * 21 + 1] = (byte) ((a[21] >> 4) & 15);
        e[2 * 22] = (byte) (a[22] & 15);
        e[2 * 22 + 1] = (byte) ((a[22] >> 4) & 15);
        e[2 * 23] = (byte) (a[23] & 15);
        e[2 * 23 + 1] = (byte) ((a[23] >> 4) & 15);
        e[2 * 24] = (byte) (a[24] & 15);
        e[2 * 24 + 1] = (byte) ((a[24] >> 4) & 15);
        e[2 * 25] = (byte) (a[25] & 15);
        e[2 * 25 + 1] = (byte) ((a[25] >> 4) & 15);
        e[2 * 26] = (byte) (a[26] & 15);
        e[2 * 26 + 1] = (byte) ((a[26] >> 4) & 15);
        e[2 * 27] = (byte) (a[27] & 15);
        e[2 * 27 + 1] = (byte) ((a[27] >> 4) & 15);
        e[2 * 28] = (byte) (a[28] & 15);
        e[2 * 28 + 1] = (byte) ((a[28] >> 4) & 15);
        e[2 * 29] = (byte) (a[29] & 15);
        e[2 * 29 + 1] = (byte) ((a[29] >> 4) & 15);
        e[2 * 30] = (byte) (a[30] & 15);
        e[2 * 30 + 1] = (byte) ((a[30] >> 4) & 15);
        e[2 * 31] = (byte) (a[31] & 15);
        e[2 * 31 + 1] = (byte) ((a[31] >> 4) & 15);
        /* each e[i] is between 0 and 15 */
        /* e[63] is between 0 and 7 */
        int carry = 0;
        e[0] = (byte) (e[0] + carry);
        carry = e[0] + 8;
        carry = carry >> 4;
        e[0] = (byte) (e[0] - (carry << 4));
        e[1] = (byte) (e[1] + carry);
        carry = e[1] + 8;
        carry = carry >> 4;
        e[1] = (byte) (e[1] - (carry << 4));
        e[2] = (byte) (e[2] + carry);
        carry = e[2] + 8;
        carry = carry >> 4;
        e[2] = (byte) (e[2] - (carry << 4));
        e[3] = (byte) (e[3] + carry);
        carry = e[3] + 8;
        carry = carry >> 4;
        e[3] = (byte) (e[3] - (carry << 4));
        e[4] = (byte) (e[4] + carry);
        carry = e[4] + 8;
        carry = carry >> 4;
        e[4] = (byte) (e[4] - (carry << 4));
        e[5] = (byte) (e[5] + carry);
        carry = e[5] + 8;
        carry = carry >> 4;
        e[5] = (byte) (e[5] - (carry << 4));
        e[6] = (byte) (e[6] + carry);
        carry = e[6] + 8;
        carry = carry >> 4;
        e[6] = (byte) (e[6] - (carry << 4));
        e[7] = (byte) (e[7] + carry);
        carry = e[7] + 8;
        carry = carry >> 4;
        e[7] = (byte) (e[7] - (carry << 4));
        e[8] = (byte) (e[8] + carry);
        carry = e[8] + 8;
        carry = carry >> 4;
        e[8] = (byte) (e[8] - (carry << 4));
        e[9] = (byte) (e[9] + carry);
        carry = e[9] + 8;
        carry = carry >> 4;
        e[9] = (byte) (e[9] - (carry << 4));
        e[10] = (byte) (e[10] + carry);
        carry = e[10] + 8;
        carry = carry >> 4;
        e[10] = (byte) (e[10] - (carry << 4));
        e[11] = (byte) (e[11] + carry);
        carry = e[11] + 8;
        carry = carry >> 4;
        e[11] = (byte) (e[11] - (carry << 4));
        e[12] = (byte) (e[12] + carry);
        carry = e[12] + 8;
        carry = carry >> 4;
        e[12] = (byte) (e[12] - (carry << 4));
        e[13] = (byte) (e[13] + carry);
        carry = e[13] + 8;
        carry = carry >> 4;
        e[13] = (byte) (e[13] - (carry << 4));
        e[14] = (byte) (e[14] + carry);
        carry = e[14] + 8;
        carry = carry >> 4;
        e[14] = (byte) (e[14] - (carry << 4));
        e[15] = (byte) (e[15] + carry);
        carry = e[15] + 8;
        carry = carry >> 4;
        e[15] = (byte) (e[15] - (carry << 4));
        e[16] = (byte) (e[16] + carry);
        carry = e[16] + 8;
        carry = carry >> 4;
        e[16] = (byte) (e[16] - (carry << 4));
        e[17] = (byte) (e[17] + carry);
        carry = e[17] + 8;
        carry = carry >> 4;
        e[17] = (byte) (e[17] - (carry << 4));
        e[18] = (byte) (e[18] + carry);
        carry = e[18] + 8;
        carry = carry >> 4;
        e[18] = (byte) (e[18] - (carry << 4));
        e[19] = (byte) (e[19] + carry);
        carry = e[19] + 8;
        carry = carry >> 4;
        e[19] = (byte) (e[19] - (carry << 4));
        e[20] = (byte) (e[20] + carry);
        carry = e[20] + 8;
        carry = carry >> 4;
        e[20] = (byte) (e[20] - (carry << 4));
        e[21] = (byte) (e[21] + carry);
        carry = e[21] + 8;
        carry = carry >> 4;
        e[21] = (byte) (e[21] - (carry << 4));
        e[22] = (byte) (e[22] + carry);
        carry = e[22] + 8;
        carry = carry >> 4;
        e[22] = (byte) (e[22] - (carry << 4));
        e[23] = (byte) (e[23] + carry);
        carry = e[23] + 8;
        carry = carry >> 4;
        e[23] = (byte) (e[23] - (carry << 4));
        e[24] = (byte) (e[24] + carry);
        carry = e[24] + 8;
        carry = carry >> 4;
        e[24] = (byte) (e[24] - (carry << 4));
        e[25] = (byte) (e[25] + carry);
        carry = e[25] + 8;
        carry = carry >> 4;
        e[25] = (byte) (e[25] - (carry << 4));
        e[26] = (byte) (e[26] + carry);
        carry = e[26] + 8;
        carry = carry >> 4;
        e[26] = (byte) (e[26] - (carry << 4));
        e[27] = (byte) (e[27] + carry);
        carry = e[27] + 8;
        carry = carry >> 4;
        e[27] = (byte) (e[27] - (carry << 4));
        e[28] = (byte) (e[28] + carry);
        carry = e[28] + 8;
        carry = carry >> 4;
        e[28] = (byte) (e[28] - (carry << 4));
        e[29] = (byte) (e[29] + carry);
        carry = e[29] + 8;
        carry = carry >> 4;
        e[29] = (byte) (e[29] - (carry << 4));
        e[30] = (byte) (e[30] + carry);
        carry = e[30] + 8;
        carry = carry >> 4;
        e[30] = (byte) (e[30] - (carry << 4));
        e[31] = (byte) (e[31] + carry);
        carry = e[31] + 8;
        carry = carry >> 4;
        e[31] = (byte) (e[31] - (carry << 4));
        e[32] = (byte) (e[32] + carry);
        carry = e[32] + 8;
        carry = carry >> 4;
        e[32] = (byte) (e[32] - (carry << 4));
        e[33] = (byte) (e[33] + carry);
        carry = e[33] + 8;
        carry = carry >> 4;
        e[33] = (byte) (e[33] - (carry << 4));
        e[34] = (byte) (e[34] + carry);
        carry = e[34] + 8;
        carry = carry >> 4;
        e[34] = (byte) (e[34] - (carry << 4));
        e[35] = (byte) (e[35] + carry);
        carry = e[35] + 8;
        carry = carry >> 4;
        e[35] = (byte) (e[35] - (carry << 4));
        e[36] = (byte) (e[36] + carry);
        carry = e[36] + 8;
        carry = carry >> 4;
        e[36] = (byte) (e[36] - (carry << 4));
        e[37] = (byte) (e[37] + carry);
        carry = e[37] + 8;
        carry = carry >> 4;
        e[37] = (byte) (e[37] - (carry << 4));
        e[38] = (byte) (e[38] + carry);
        carry = e[38] + 8;
        carry = carry >> 4;
        e[38] = (byte) (e[38] - (carry << 4));
        e[39] = (byte) (e[39] + carry);
        carry = e[39] + 8;
        carry = carry >> 4;
        e[39] = (byte) (e[39] - (carry << 4));
        e[40] = (byte) (e[40] + carry);
        carry = e[40] + 8;
        carry = carry >> 4;
        e[40] = (byte) (e[40] - (carry << 4));
        e[41] = (byte) (e[41] + carry);
        carry = e[41] + 8;
        carry = carry >> 4;
        e[41] = (byte) (e[41] - (carry << 4));
        e[42] = (byte) (e[42] + carry);
        carry = e[42] + 8;
        carry = carry >> 4;
        e[42] = (byte) (e[42] - (carry << 4));
        e[43] = (byte) (e[43] + carry);
        carry = e[43] + 8;
        carry = carry >> 4;
        e[43] = (byte) (e[43] - (carry << 4));
        e[44] = (byte) (e[44] + carry);
        carry = e[44] + 8;
        carry = carry >> 4;
        e[44] = (byte) (e[44] - (carry << 4));
        e[45] = (byte) (e[45] + carry);
        carry = e[45] + 8;
        carry = carry >> 4;
        e[45] = (byte) (e[45] - (carry << 4));
        e[46] = (byte) (e[46] + carry);
        carry = e[46] + 8;
        carry = carry >> 4;
        e[46] = (byte) (e[46] - (carry << 4));
        e[47] = (byte) (e[47] + carry);
        carry = e[47] + 8;
        carry = carry >> 4;
        e[47] = (byte) (e[47] - (carry << 4));
        e[48] = (byte) (e[48] + carry);
        carry = e[48] + 8;
        carry = carry >> 4;
        e[48] = (byte) (e[48] - (carry << 4));
        e[49] = (byte) (e[49] + carry);
        carry = e[49] + 8;
        carry = carry >> 4;
        e[49] = (byte) (e[49] - (carry << 4));
        e[50] = (byte) (e[50] + carry);
        carry = e[50] + 8;
        carry = carry >> 4;
        e[50] = (byte) (e[50] - (carry << 4));
        e[51] = (byte) (e[51] + carry);
        carry = e[51] + 8;
        carry = carry >> 4;
        e[51] = (byte) (e[51] - (carry << 4));
        e[52] = (byte) (e[52] + carry);
        carry = e[52] + 8;
        carry = carry >> 4;
        e[52] = (byte) (e[52] - (carry << 4));
        e[53] = (byte) (e[53] + carry);
        carry = e[53] + 8;
        carry = carry >> 4;
        e[53] = (byte) (e[53] - (carry << 4));
        e[54] = (byte) (e[54] + carry);
        carry = e[54] + 8;
        carry = carry >> 4;
        e[54] = (byte) (e[54] - (carry << 4));
        e[55] = (byte) (e[55] + carry);
        carry = e[55] + 8;
        carry = carry >> 4;
        e[55] = (byte) (e[55] - (carry << 4));
        e[56] = (byte) (e[56] + carry);
        carry = e[56] + 8;
        carry = carry >> 4;
        e[56] = (byte) (e[56] - (carry << 4));
        e[57] = (byte) (e[57] + carry);
        carry = e[57] + 8;
        carry = carry >> 4;
        e[57] = (byte) (e[57] - (carry << 4));
        e[58] = (byte) (e[58] + carry);
        carry = e[58] + 8;
        carry = carry >> 4;
        e[58] = (byte) (e[58] - (carry << 4));
        e[59] = (byte) (e[59] + carry);
        carry = e[59] + 8;
        carry = carry >> 4;
        e[59] = (byte) (e[59] - (carry << 4));
        e[60] = (byte) (e[60] + carry);
        carry = e[60] + 8;
        carry = carry >> 4;
        e[60] = (byte) (e[60] - (carry << 4));
        e[61] = (byte) (e[61] + carry);
        carry = e[61] + 8;
        carry = carry >> 4;
        e[61] = (byte) (e[61] - (carry << 4));
        e[62] = (byte) (e[62] + carry);
        carry = e[62] + 8;
        carry = carry >> 4;
        e[62] = (byte) (e[62] - (carry << 4));
        e[63] = (byte) (e[63] + carry);
        /* each e[i] is between -8 and 7 */
        return e;
    }

    abstract Representation getRepr();

    abstract FieldElement getX();

    abstract FieldElement getY();

    abstract FieldElement getZ();

    abstract FieldElement getT();

    abstract GroupElement[][] getPrecmp();

    abstract GroupElement[] getDblPrecmp();

    abstract Curve getCurve();

    abstract Representation getRepresentation();

    abstract byte[] toByteArray();

    abstract GroupElement[][] precomputeSingle();

    abstract GroupElement[] precomputeDouble();

    abstract GroupElement dbl();

    abstract GroupElement madd(GroupElement q);

    abstract GroupElement msub(GroupElement q);

    abstract GroupElement add(GroupElement q);

    abstract GroupElement sub(GroupElement q);

    abstract GroupElement negate();

    @Override
    abstract int hashCode();

    @Override
    abstract boolean equals(Object obj);

    PrecompGroupElement cmov(GroupElement u, int b);

    PrecompGroupElement select(int pos, int b);

    abstract GroupElement scalarMultiply(byte[] a);

    abstract GroupElement doubleScalarMultiplyVariableTime(GroupElement A, byte[] a, byte[] b);

    abstract boolean isOnCurve();

    abstract boolean isOnCurve(Curve curve);

    @Override
    abstract String toString();
}
