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
package net.i2p.crypto.eddsa.math.bigint;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.math.BigInteger;

import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.EdDSAFiniteField;
import net.i2p.crypto.eddsa.math.ScalarOps;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

import org.jetbrains.annotations.NotNull;
import org.junit.Test;

/**
 * @author str4d
 *
 */
public class BigIntegerScalarOpsTest {

    private static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
    private static final EdDSAFiniteField ED_25519_ED_DSA_FINITE_FIELD = ed25519.curve.getEdDSAFiniteField();

    /**
     * Test method for {@link net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps#reduce(byte[])}.
     */
    @Test
    public void testReduce() {
        @NotNull final ScalarOps sc = new BigIntegerScalarOps(ED_25519_ED_DSA_FINITE_FIELD,
                new BigInteger("5"));
        assertThat(sc.reduce(new byte[] {(byte) 7}),
                is(equalTo(Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000"))));

        @NotNull final ScalarOps sc2 = new BigIntegerScalarOps(ED_25519_ED_DSA_FINITE_FIELD,
                new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989"));
        // Example from test case 1
        @NotNull final byte[] r = Utils.hexToBytes("b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d");
        assertThat(sc2.reduce(r), is(equalTo(Utils.hexToBytes("f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404"))));
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps#multiplyAndAdd(byte[], byte[], byte[])}.
     */
    @Test
    public void testMultiplyAndAdd() {
        @NotNull final ScalarOps sc = new BigIntegerScalarOps(ED_25519_ED_DSA_FINITE_FIELD,
                new BigInteger("5"));
        assertThat(sc.multiplyAndAdd(new byte[] {(byte) 7}, new byte[] {(byte) 2}, new byte[] {(byte) 5}),
                is(equalTo(Utils.hexToBytes("0400000000000000000000000000000000000000000000000000000000000000"))));

        @NotNull final ScalarOps sc2 = new BigIntegerScalarOps(ED_25519_ED_DSA_FINITE_FIELD,
                new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989"));
        // Example from test case 1
        @NotNull final byte[] h = Utils.hexToBytes("86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e525404");
        @NotNull final byte[] a = Utils.hexToBytes("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f");
        @NotNull final byte[] r = Utils.hexToBytes("f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404");
        @NotNull final byte[] S = Utils.hexToBytes("5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        assertThat(sc2.multiplyAndAdd(h, a, r), is(equalTo(S)));
    }

}
