/**
 * EdDSA-Java by str4d
 *
 * To the extent possible under law, the person who associated CC0 with
 * EdDSA-Java has waived all copyright and related or neighboring rights
 * to EdDSA-Java.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 *
 */
package net.i2p.crypto.eddsa.math.ed25519;

import net.i2p.crypto.eddsa.math.ScalarOps;
import org.jetbrains.annotations.NotNull;

import static net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding.load_3;
import static net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding.load_4;

/**
 * Class for reducing a huge integer modulo the group order q and
 * doing a combined multiply plus add plus reduce operation.
 * <p>
 * $q = 2^{252} + 27742317777372353535851937790883648493$.
 * <p>
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 */
public class Ed25519ScalarOps implements ScalarOps {

    /**
     * Reduction modulo the group order $q$.
     * <p>
     * Input:
     *   $s[0]+256*s[1]+\dots+256^{63}*s[63] = s$
     * <p>
     * Output:
     *   $s[0]+256*s[1]+\dots+256^{31}*s[31] = s \bmod q$
     *   where $q = 2^{252} + 27742317777372353535851937790883648493$.
     */
    @NotNull
    public byte[] reduce(@NotNull final byte[] s) {
        // s0,..., s22 have 21 bits, s23 has 29 bits
        long s0 = (long) (0x1FFFFF & load_3(s, 0));
        long s1 = 0x1FFFFFL & (load_4(s, 2) >> 5);
        long s2 = (long) (0x1FFFFF & (load_3(s, 5) >> 2));
        long s3 = 0x1FFFFFL & (load_4(s, 7) >> 7);
        long s4 = 0x1FFFFFL & (load_4(s, 10) >> 4);
        long s5 = (long) (0x1FFFFF & (load_3(s, 13) >> 1));
        long s6 = 0x1FFFFFL & (load_4(s, 15) >> 6);
        long s7 = (long) (0x1FFFFF & (load_3(s, 18) >> 3));
        long s8 = (long) (0x1FFFFF & load_3(s, 21));
        long s9 = 0x1FFFFFL & (load_4(s, 23) >> 5);
        long s10 = (long) (0x1FFFFF & (load_3(s, 26) >> 2));
        long s11 = 0x1FFFFFL & (load_4(s, 28) >> 7);
        long s12 = 0x1FFFFFL & (load_4(s, 31) >> 4);
        long s13 = (long) (0x1FFFFF & (load_3(s, 34) >> 1));
        long s14 = 0x1FFFFFL & (load_4(s, 36) >> 6);
        long s15 = (long) (0x1FFFFF & (load_3(s, 39) >> 3));
        long s16 = (long) (0x1FFFFF & load_3(s, 42));
        long s17 = 0x1FFFFFL & (load_4(s, 44) >> 5);
        final long s18 = (long) (0x1FFFFF & (load_3(s, 47) >> 2));
        final long s19 = 0x1FFFFFL & (load_4(s, 49) >> 7);
        final long s20 = 0x1FFFFFL & (load_4(s, 52) >> 4);
        final long s21 = (long) (0x1FFFFF & (load_3(s, 55) >> 1));
        final long s22 = 0x1FFFFFL & (load_4(s, 57) >> 6);
        final long s23 = (load_4(s, 60) >> 3);
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;
        long carry10;
        long carry11;
        final long carry12;
        final long carry13;
        final long carry14;
        final long carry15;
        final long carry16;

        /**
         * Lots of magic numbers :)
         * To understand what's going on below, note that
         *
         * (1) q = 2^252 + q0 where q0 = 27742317777372353535851937790883648493.
         * (2) s11 is the coefficient of 2^(11*21), s23 is the coefficient of 2^(^23*21) and 2^252 = 2^((23-11) * 21)).
         * (3) 2^252 congruent -q0 modulo q.
         * (4) -q0 = 666643 * 2^0 + 470296 * 2^21 + 654183 * 2^(2*21) - 997805 * 2^(3*21) + 136657 * 2^(4*21) - 683901 * 2^(5*21)
         *
         * Thus
         * s23 * 2^(23*11) = s23 * 2^(12*21) * 2^(11*21) = s3 * 2^252 * 2^(11*21) congruent
         * s23 * (666643 * 2^0 + 470296 * 2^21 + 654183 * 2^(2*21) - 997805 * 2^(3*21) + 136657 * 2^(4*21) - 683901 * 2^(5*21)) * 2^(11*21) modulo q =
         * s23 * (666643 * 2^(11*21) + 470296 * 2^(12*21) + 654183 * 2^(13*21) - 997805 * 2^(14*21) + 136657 * 2^(15*21) - 683901 * 2^(16*21)).
         *
         * The same procedure is then applied for s22,...,s18.
         */
        s11 += s23 * 666643L;
        s12 += s23 * 470296L;
        s13 += s23 * 654183L;
        s14 -= s23 * 997805L;
        s15 += s23 * 136657L;
        s16 -= s23 * 683901L;
        // not used again
        //s23 = 0;

        s10 += s22 * 666643L;
        s11 += s22 * 470296L;
        s12 += s22 * 654183L;
        s13 -= s22 * 997805L;
        s14 += s22 * 136657L;
        s15 -= s22 * 683901L;
        // not used again
        //s22 = 0;

        s9 += s21 * 666643L;
        s10 += s21 * 470296L;
        s11 += s21 * 654183L;
        s12 -= s21 * 997805L;
        s13 += s21 * 136657L;
        s14 -= s21 * 683901L;
        // not used again
        //s21 = 0;

        s8 += s20 * 666643L;
        s9 += s20 * 470296L;
        s10 += s20 * 654183L;
        s11 -= s20 * 997805L;
        s12 += s20 * 136657L;
        s13 -= s20 * 683901L;
        // not used again
        //s20 = 0;

        s7 += s19 * 666643L;
        s8 += s19 * 470296L;
        s9 += s19 * 654183L;
        s10 -= s19 * 997805L;
        s11 += s19 * 136657L;
        s12 -= s19 * 683901L;
        // not used again
        //s19 = 0;

        s6 += s18 * 666643L;
        s7 += s18 * 470296L;
        s8 += s18 * 654183L;
        s9 -= s18 * 997805L;
        s10 += s18 * 136657L;
        s11 -= s18 * 683901L;
        // not used again
        //s18 = 0;

        /**
         * Time to reduce the coefficient in order not to get an overflow.
         */
        carry6 = (s6 + (long) (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (long) (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (long) (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry12 = (s12 + (long) (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
        carry14 = (s14 + (long) (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
        carry16 = (s16 + (long) (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

        carry7 = (s7 + (long) (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (long) (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (long) (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry13 = (s13 + (long) (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
        carry15 = (s15 + (long) (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

        /**
         * Continue with above procedure.
         */
        s5 += s17 * 666643L;
        s6 += s17 * 470296L;
        s7 += s17 * 654183L;
        s8 -= s17 * 997805L;
        s9 += s17 * 136657L;
        s10 -= s17 * 683901L;
        // not used again
        //s17 = 0;

        s4 += s16 * 666643L;
        s5 += s16 * 470296L;
        s6 += s16 * 654183L;
        s7 -= s16 * 997805L;
        s8 += s16 * 136657L;
        s9 -= s16 * 683901L;
        // not used again
        //s16 = 0;

        s3 += s15 * 666643L;
        s4 += s15 * 470296L;
        s5 += s15 * 654183L;
        s6 -= s15 * 997805L;
        s7 += s15 * 136657L;
        s8 -= s15 * 683901L;
        // not used again
        //s15 = 0;

        s2 += s14 * 666643L;
        s3 += s14 * 470296L;
        s4 += s14 * 654183L;
        s5 -= s14 * 997805L;
        s6 += s14 * 136657L;
        s7 -= s14 * 683901L;
        // not used again
        //s14 = 0;

        s1 += s13 * 666643L;
        s2 += s13 * 470296L;
        s3 += s13 * 654183L;
        s4 -= s13 * 997805L;
        s5 += s13 * 136657L;
        s6 -= s13 * 683901L;
        // not used again
        //s13 = 0;

        s0 += s12 * 666643L;
        s1 += s12 * 470296L;
        s2 += s12 * 654183L;
        s3 -= s12 * 997805L;
        s4 += s12 * 136657L;
        s5 -= s12 * 683901L;
        // set below
        //s12 = 0;

        /**
         * Reduce coefficients again.
         */
        carry0 = (s0 + (long) (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry2 = (s2 + (long) (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry4 = (s4 + (long) (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry6 = (s6 + (long) (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (long) (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (long) (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

        carry1 = (s1 + (long) (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry3 = (s3 + (long) (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry5 = (s5 + (long) (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry7 = (s7 + (long) (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (long) (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        //carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = (s11 + (long) (1 << 20)) >> 21;
        long s12a = carry11;
        s11 -= carry11 << 21;

        s0 += s12a * 666643L;
        s1 += s12a * 470296L;
        s2 += s12a * 654183L;
        s3 -= s12a * 997805L;
        s4 += s12a * 136657L;
        s5 -= s12a * 683901L;
        // set below
        //s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
        //carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = s11 >> 21;
        long s12b = carry11;
        s11 -= carry11 << 21;

        // TODO-CR BR: Is it really needed to do it TWO times? (it doesn't hurt, just a question).
        s0 += s12b * 666643L;
        s1 += s12b * 470296L;
        s2 += s12b * 654183L;
        s3 -= s12b * 997805L;
        s4 += s12b * 136657L;
        s5 -= s12b * 683901L;
        // not used again
        //s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

        // s0, ..., s11 got 21 bits each.
        @NotNull final byte[] result = new byte[32];
        result[0] = (byte) s0;
        result[1] = (byte) (s0 >> 8);
        result[2] = (byte) ((s0 >> 16) | (s1 << 5));
        result[3] = (byte) (s1 >> 3);
        result[4] = (byte) (s1 >> 11);
        result[5] = (byte) ((s1 >> 19) | (s2 << 2));
        result[6] = (byte) (s2 >> 6);
        result[7] = (byte) ((s2 >> 14) | (s3 << 7));
        result[8] = (byte) (s3 >> 1);
        result[9] = (byte) (s3 >> 9);
        result[10] = (byte) ((s3 >> 17) | (s4 << 4));
        result[11] = (byte) (s4 >> 4);
        result[12] = (byte) (s4 >> 12);
        result[13] = (byte) ((s4 >> 20) | (s5 << 1));
        result[14] = (byte) (s5 >> 7);
        result[15] = (byte) ((s5 >> 15) | (s6 << 6));
        result[16] = (byte) (s6 >> 2);
        result[17] = (byte) (s6 >> 10);
        result[18] = (byte) ((s6 >> 18) | (s7 << 3));
        result[19] = (byte) (s7 >> 5);
        result[20] = (byte) (s7 >> 13);
        result[21] = (byte) s8;
        result[22] = (byte) (s8 >> 8);
        result[23] = (byte) ((s8 >> 16) | (s9 << 5));
        result[24] = (byte) (s9 >> 3);
        result[25] = (byte) (s9 >> 11);
        result[26] = (byte) ((s9 >> 19) | (s10 << 2));
        result[27] = (byte) (s10 >> 6);
        result[28] = (byte) ((s10 >> 14) | (s11 << 7));
        result[29] = (byte) (s11 >> 1);
        result[30] = (byte) (s11 >> 9);
        result[31] = (byte) (s11 >> 17);
        return result;
    }


    /**
     * $(ab+c) \bmod q$
     * <p>
     * Input:
     * </p><ul>
     * <li>$a[0]+256*a[1]+\dots+256^{31}*a[31] = a$
     * <li>$b[0]+256*b[1]+\dots+256^{31}*b[31] = b$
     * <li>$c[0]+256*c[1]+\dots+256^{31}*c[31] = c$
     * </ul><p>
     * Output:
     *   $result[0]+256*result[1]+\dots+256^{31}*result[31] = (ab+c) \bmod q$
     *   where $q = 2^{252} + 27742317777372353535851937790883648493$.
     * <p>
     * See the comments in {@link #reduce(byte[])} for an explanation of the algorithm.
     */
    @NotNull
    public byte[] multiplyAndAdd(@NotNull final byte[] a, @NotNull final byte[] b, @NotNull final byte[] c) {
        final long a0 = (long) (0x1FFFFF & load_3(a, 0));
        final long a1 = 0x1FFFFFL & (load_4(a, 2) >> 5);
        final long a2 = (long) (0x1FFFFF & (load_3(a, 5) >> 2));
        final long a3 = 0x1FFFFFL & (load_4(a, 7) >> 7);
        final long a4 = 0x1FFFFFL & (load_4(a, 10) >> 4);
        final long a5 = (long) (0x1FFFFF & (load_3(a, 13) >> 1));
        final long a6 = 0x1FFFFFL & (load_4(a, 15) >> 6);
        final long a7 = (long) (0x1FFFFF & (load_3(a, 18) >> 3));
        final long a8 = (long) (0x1FFFFF & load_3(a, 21));
        final long a9 = 0x1FFFFFL & (load_4(a, 23) >> 5);
        final long a10 = (long) (0x1FFFFF & (load_3(a, 26) >> 2));
        final long a11 = (load_4(a, 28) >> 7);
        final long b0 = (long) (0x1FFFFF & load_3(b, 0));
        final long b1 = 0x1FFFFFL & (load_4(b, 2) >> 5);
        final long b2 = (long) (0x1FFFFF & (load_3(b, 5) >> 2));
        final long b3 = 0x1FFFFFL & (load_4(b, 7) >> 7);
        final long b4 = 0x1FFFFFL & (load_4(b, 10) >> 4);
        final long b5 = (long) (0x1FFFFF & (load_3(b, 13) >> 1));
        final long b6 = 0x1FFFFFL & (load_4(b, 15) >> 6);
        final long b7 = (long) (0x1FFFFF & (load_3(b, 18) >> 3));
        final long b8 = (long) (0x1FFFFF & load_3(b, 21));
        final long b9 = 0x1FFFFFL & (load_4(b, 23) >> 5);
        final long b10 = (long) (0x1FFFFF & (load_3(b, 26) >> 2));
        final long b11 = (load_4(b, 28) >> 7);
        final long c0 = (long) (0x1FFFFF & load_3(c, 0));
        final long c1 = 0x1FFFFFL & (load_4(c, 2) >> 5);
        final long c2 = (long) (0x1FFFFF & (load_3(c, 5) >> 2));
        final long c3 = 0x1FFFFFL & (load_4(c, 7) >> 7);
        final long c4 = 0x1FFFFFL & (load_4(c, 10) >> 4);
        final long c5 = (long) (0x1FFFFF & (load_3(c, 13) >> 1));
        final long c6 = 0x1FFFFFL & (load_4(c, 15) >> 6);
        final long c7 = (long) (0x1FFFFF & (load_3(c, 18) >> 3));
        final long c8 = (long) (0x1FFFFF & load_3(c, 21));
        final long c9 = 0x1FFFFFL & (load_4(c, 23) >> 5);
        final long c10 = (long) (0x1FFFFF & (load_3(c, 26) >> 2));
        final long c11 = (load_4(c, 28) >> 7);
        long s0;
        long s1;
        long s2;
        long s3;
        long s4;
        long s5;
        long s6;
        long s7;
        long s8;
        long s9;
        long s10;
        long s11;
        long s12;
        long s13;
        long s14;
        long s15;
        long s16;
        long s17;
        long s18;
        long s19;
        long s20;
        long s21;
        long s22;
        final long s23;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;
        long carry10;
        long carry11;
        long carry12;
        long carry13;
        long carry14;
        long carry15;
        long carry16;
        final long carry17;
        final long carry18;
        final long carry19;
        final long carry20;
        final long carry21;
        final long carry22;

        s0 = c0 + a0*b0;
        s1 = c1 + a0*b1 + a1*b0;
        s2 = c2 + a0*b2 + a1*b1 + a2*b0;
        s3 = c3 + a0*b3 + a1*b2 + a2*b1 + a3*b0;
        s4 = c4 + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0;
        s5 = c5 + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0;
        s6 = c6 + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0;
        s7 = c7 + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0;
        s8 = c8 + a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0;
        s9 = c9 + a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0;
        s10 = c10 + a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0;
        s11 = c11 + a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0;
        s12 = a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1;
        s13 = a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2;
        s14 = a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3;
        s15 = a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4;
        s16 = a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5;
        s17 = a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6;
        s18 = a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7;
        s19 = a8*b11 + a9*b10 + a10*b9 + a11*b8;
        s20 = a9*b11 + a10*b10 + a11*b9;
        s21 = a10*b11 + a11*b10;
        s22 = a11*b11;
        // set below
        //s23 = 0;

        carry0 = (s0 + (long) (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry2 = (s2 + (long) (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry4 = (s4 + (long) (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry6 = (s6 + (long) (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (long) (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (long) (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry12 = (s12 + (long) (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
        carry14 = (s14 + (long) (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
        carry16 = (s16 + (long) (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21;
        carry18 = (s18 + (long) (1 << 20)) >> 21; s19 += carry18; s18 -= carry18 << 21;
        carry20 = (s20 + (long) (1 << 20)) >> 21; s21 += carry20; s20 -= carry20 << 21;
        //carry22 = (s22 + (1<<20)) >> 21; s23 += carry22; s22 -= carry22 << 21;
        carry22 = (s22 + (long) (1 << 20)) >> 21; s23 = carry22; s22 -= carry22 << 21;

        carry1 = (s1 + (long) (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry3 = (s3 + (long) (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry5 = (s5 + (long) (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry7 = (s7 + (long) (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (long) (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (long) (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry13 = (s13 + (long) (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
        carry15 = (s15 + (long) (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21;
        carry17 = (s17 + (long) (1 << 20)) >> 21; s18 += carry17; s17 -= carry17 << 21;
        carry19 = (s19 + (long) (1 << 20)) >> 21; s20 += carry19; s19 -= carry19 << 21;
        carry21 = (s21 + (long) (1 << 20)) >> 21; s22 += carry21; s21 -= carry21 << 21;

        s11 += s23 * 666643L;
        s12 += s23 * 470296L;
        s13 += s23 * 654183L;
        s14 -= s23 * 997805L;
        s15 += s23 * 136657L;
        s16 -= s23 * 683901L;
        // not used again
        //s23 = 0;

        s10 += s22 * 666643L;
        s11 += s22 * 470296L;
        s12 += s22 * 654183L;
        s13 -= s22 * 997805L;
        s14 += s22 * 136657L;
        s15 -= s22 * 683901L;
        // not used again
        //s22 = 0;

        s9 += s21 * 666643L;
        s10 += s21 * 470296L;
        s11 += s21 * 654183L;
        s12 -= s21 * 997805L;
        s13 += s21 * 136657L;
        s14 -= s21 * 683901L;
        // not used again
        //s21 = 0;

        s8 += s20 * 666643L;
        s9 += s20 * 470296L;
        s10 += s20 * 654183L;
        s11 -= s20 * 997805L;
        s12 += s20 * 136657L;
        s13 -= s20 * 683901L;
        // not used again
        //s20 = 0;

        s7 += s19 * 666643L;
        s8 += s19 * 470296L;
        s9 += s19 * 654183L;
        s10 -= s19 * 997805L;
        s11 += s19 * 136657L;
        s12 -= s19 * 683901L;
        // not used again
        //s19 = 0;

        s6 += s18 * 666643L;
        s7 += s18 * 470296L;
        s8 += s18 * 654183L;
        s9 -= s18 * 997805L;
        s10 += s18 * 136657L;
        s11 -= s18 * 683901L;
        // not used again
        //s18 = 0;

        carry6 = (s6 + (long) (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (long) (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (long) (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry12 = (s12 + (long) (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
        carry14 = (s14 + (long) (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
        carry16 = (s16 + (long) (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

        carry7 = (s7 + (long) (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (long) (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (long) (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry13 = (s13 + (long) (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
        carry15 = (s15 + (long) (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

        s5 += s17 * 666643L;
        s6 += s17 * 470296L;
        s7 += s17 * 654183L;
        s8 -= s17 * 997805L;
        s9 += s17 * 136657L;
        s10 -= s17 * 683901L;
        // not used again
        //s17 = 0;

        s4 += s16 * 666643L;
        s5 += s16 * 470296L;
        s6 += s16 * 654183L;
        s7 -= s16 * 997805L;
        s8 += s16 * 136657L;
        s9 -= s16 * 683901L;
        // not used again
        //s16 = 0;

        s3 += s15 * 666643L;
        s4 += s15 * 470296L;
        s5 += s15 * 654183L;
        s6 -= s15 * 997805L;
        s7 += s15 * 136657L;
        s8 -= s15 * 683901L;
        // not used again
        //s15 = 0;

        s2 += s14 * 666643L;
        s3 += s14 * 470296L;
        s4 += s14 * 654183L;
        s5 -= s14 * 997805L;
        s6 += s14 * 136657L;
        s7 -= s14 * 683901L;
        // not used again
        //s14 = 0;

        s1 += s13 * 666643L;
        s2 += s13 * 470296L;
        s3 += s13 * 654183L;
        s4 -= s13 * 997805L;
        s5 += s13 * 136657L;
        s6 -= s13 * 683901L;
        // not used again
        //s13 = 0;

        s0 += s12 * 666643L;
        s1 += s12 * 470296L;
        s2 += s12 * 654183L;
        s3 -= s12 * 997805L;
        s4 += s12 * 136657L;
        s5 -= s12 * 683901L;
        // set below
        //s12 = 0;

        carry0 = (s0 + (long) (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry2 = (s2 + (long) (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry4 = (s4 + (long) (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry6 = (s6 + (long) (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (long) (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (long) (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

        carry1 = (s1 + (long) (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry3 = (s3 + (long) (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry5 = (s5 + (long) (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry7 = (s7 + (long) (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (long) (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        //carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = (s11 + (long) (1 << 20)) >> 21; s12 = carry11; s11 -= carry11 << 21;

        s0 += s12 * 666643L;
        s1 += s12 * 470296L;
        s2 += s12 * 654183L;
        s3 -= s12 * 997805L;
        s4 += s12 * 136657L;
        s5 -= s12 * 683901L;
        // set below
        //s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
        //carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;
        carry11 = s11 >> 21; s12 = carry11; s11 -= carry11 << 21;

        s0 += s12 * 666643L;
        s1 += s12 * 470296L;
        s2 += s12 * 654183L;
        s3 -= s12 * 997805L;
        s4 += s12 * 136657L;
        s5 -= s12 * 683901L;
        // not used again
        //s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

        @NotNull final byte[] result = new byte[32];
        result[0] = (byte) s0;
        result[1] = (byte) (s0 >> 8);
        result[2] = (byte) ((s0 >> 16) | (s1 << 5));
        result[3] = (byte) (s1 >> 3);
        result[4] = (byte) (s1 >> 11);
        result[5] = (byte) ((s1 >> 19) | (s2 << 2));
        result[6] = (byte) (s2 >> 6);
        result[7] = (byte) ((s2 >> 14) | (s3 << 7));
        result[8] = (byte) (s3 >> 1);
        result[9] = (byte) (s3 >> 9);
        result[10] = (byte) ((s3 >> 17) | (s4 << 4));
        result[11] = (byte) (s4 >> 4);
        result[12] = (byte) (s4 >> 12);
        result[13] = (byte) ((s4 >> 20) | (s5 << 1));
        result[14] = (byte) (s5 >> 7);
        result[15] = (byte) ((s5 >> 15) | (s6 << 6));
        result[16] = (byte) (s6 >> 2);
        result[17] = (byte) (s6 >> 10);
        result[18] = (byte) ((s6 >> 18) | (s7 << 3));
        result[19] = (byte) (s7 >> 5);
        result[20] = (byte) (s7 >> 13);
        result[21] = (byte) s8;
        result[22] = (byte) (s8 >> 8);
        result[23] = (byte) ((s8 >> 16) | (s9 << 5));
        result[24] = (byte) (s9 >> 3);
        result[25] = (byte) (s9 >> 11);
        result[26] = (byte) ((s9 >> 19) | (s10 << 2));
        result[27] = (byte) (s10 >> 6);
        result[28] = (byte) ((s10 >> 14) | (s11 << 7));
        result[29] = (byte) (s11 >> 1);
        result[30] = (byte) (s11 >> 9);
        result[31] = (byte) (s11 >> 17);
        return result;
    }
}
