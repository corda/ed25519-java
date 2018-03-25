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
package net.i2p.crypto.eddsa;

import org.hamcrest.core.IsEqual;
import org.jetbrains.annotations.NotNull;
import org.junit.*;

import java.security.SecureRandom;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

/**
 * @author str4d
 * additional test by the NEM project team.
 *
 */
public class UtilsTest {
    private static final String hex1 = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    private static final String hex2 = "47a3f5b71494bcd961f3a4e859a238d6eaf8e648746d2f56a89b5e236f98d45f";
    private static final String hex3 = "5fd396e4a2b5dc9078f57e3ab5a87c28fd128e5f78cc4a97f4122dc45f6e4bb9";
    private static final byte[] bytes1 = {(byte) 59, (byte) 106, (byte) 39, (byte) -68, (byte) -50, (byte) -74, (byte) -92, (byte) 45, (byte) 98, (byte) -93, (byte) -88, (byte) -48, (byte) 42, (byte) 111, (byte) 13, (byte) 115,
            (byte) 101, (byte) 50, (byte) 21, (byte) 119, (byte) 29, (byte) -30, (byte) 67, (byte) -90, (byte) 58, (byte) -64, (byte) 72, (byte) -95, (byte) -117, (byte) 89, (byte) -38, (byte) 41};
    private static final byte[] bytes2 = {(byte) 71, (byte) -93, (byte) -11, (byte) -73, (byte) 20, (byte) -108, (byte) -68, (byte) -39, (byte) 97, (byte) -13, (byte) -92, (byte) -24, (byte) 89, (byte) -94, (byte) 56, (byte) -42,
            (byte) -22, (byte) -8, (byte) -26, (byte) 72, (byte) 116, (byte) 109, (byte) 47, (byte) 86, (byte) -88, (byte) -101, (byte) 94, (byte) 35, (byte) 111, (byte) -104, (byte) -44, (byte) 95};
    private static final byte[] bytes3 = {(byte) 95, (byte) -45, (byte) -106, (byte) -28, (byte) -94, (byte) -75, (byte) -36, (byte) -112, (byte) 120, (byte) -11, (byte) 126, (byte) 58, (byte) -75, (byte) -88, (byte) 124, (byte) 40,
            (byte) -3, (byte) 18, (byte) -114, (byte) 95, (byte) 120, (byte) -52, (byte) 74, (byte) -105, (byte) -12, (byte) 18, (byte) 45, (byte) -60, (byte) 95, (byte) 110, (byte) 75, (byte) -71};

    /**
     * Test method for {@link net.i2p.crypto.eddsa.Utils#equal(int, int)}.
     */
    @Test
    public void testIntEqual() {
        assertThat(Integer.valueOf(Utils.equal(0, 0)),       is(Integer.valueOf(1)));
        assertThat(Integer.valueOf(Utils.equal(1, 1)),       is(Integer.valueOf(1)));
        assertThat(Integer.valueOf(Utils.equal(1, 0)),       is(Integer.valueOf(0)));
        assertThat(Integer.valueOf(Utils.equal(1, 127)),     is(Integer.valueOf(0)));
        assertThat(Integer.valueOf(Utils.equal(-127, 127)),  is(Integer.valueOf(0)));
        assertThat(Integer.valueOf(Utils.equal(-42, -42)),   is(Integer.valueOf(1)));
        assertThat(Integer.valueOf(Utils.equal(255, 255)),   is(Integer.valueOf(1)));
        assertThat(Integer.valueOf(Utils.equal(-255, -256)), is(Integer.valueOf(0)));
    }

    @Test
    public void equalsReturnsOneForEqualByteArrays() {
        @NotNull final SecureRandom random = new SecureRandom();
        @NotNull final byte[] bytes1 = new byte[32];
        @NotNull final byte[] bytes2 = new byte[32];
        for (int i = 0; 100 > i; i++) {
            random.nextBytes(bytes1);
            System.arraycopy(bytes1, 0, bytes2, 0, 32);
            Assert.assertThat(Integer.valueOf(Utils.equal(bytes1, bytes2)), IsEqual.equalTo(Integer.valueOf(1)));
        }
    }

    @Test
    public void equalsReturnsZeroForUnequalByteArrays() {
        @NotNull final SecureRandom random = new SecureRandom();
        @NotNull final byte[] bytes1 = new byte[32];
        @NotNull final byte[] bytes2 = new byte[32];
        random.nextBytes(bytes1);
        for (int i = 0; 32 > i; i++) {
            System.arraycopy(bytes1, 0, bytes2, 0, 32);
            bytes2[i] = (byte) (bytes2[i] ^ 0xff);
            Assert.assertThat(Integer.valueOf(Utils.equal(bytes1, bytes2)), IsEqual.equalTo(Integer.valueOf(0)));
        }
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.Utils#equal(byte[], byte[])}.
     */
    @Test
    public void testByteArrayEqual() {
        @NotNull final byte[] zero = new byte[32];
        @NotNull final byte[] one = new byte[32];
        one[0] = (byte) 1;

        assertThat(Integer.valueOf(Utils.equal(zero, zero)), is(Integer.valueOf(1)));
        assertThat(Integer.valueOf(Utils.equal(one, one)),   is(Integer.valueOf(1)));
        assertThat(Integer.valueOf(Utils.equal(one, zero)),  is(Integer.valueOf(0)));
        assertThat(Integer.valueOf(Utils.equal(zero, one)),  is(Integer.valueOf(0)));
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.Utils#negative(int)}.
     */
    @Test
    public void testNegative() {
        assertThat(Integer.valueOf(Utils.negative(0)),    is(Integer.valueOf(0)));
        assertThat(Integer.valueOf(Utils.negative(1)),    is(Integer.valueOf(0)));
        assertThat(Integer.valueOf(Utils.negative(-1)),   is(Integer.valueOf(1)));
        assertThat(Integer.valueOf(Utils.negative(32)),   is(Integer.valueOf(0)));
        assertThat(Integer.valueOf(Utils.negative(-100)), is(Integer.valueOf(1)));
        assertThat(Integer.valueOf(Utils.negative(127)),  is(Integer.valueOf(0)));
        assertThat(Integer.valueOf(Utils.negative(-255)), is(Integer.valueOf(1)));
    }

    /**
     * Test method for {@link net.i2p.crypto.eddsa.Utils#bit(byte[], int)}.
     */
    @Test
    public void testBit() {
        assertThat(Integer.valueOf(Utils.bit(new byte[]{(byte) 0}, 0)), is(Integer.valueOf(0)));
        assertThat(Integer.valueOf(Utils.bit(new byte[]{(byte) 8}, 3)), is(Integer.valueOf(1)));
        assertThat(Integer.valueOf(Utils.bit(new byte[]{(byte) 1, (byte) 2, (byte) 3}, 9)), is(Integer.valueOf(1)));
        assertThat(Integer.valueOf(Utils.bit(new byte[]{(byte) 1, (byte) 2, (byte) 3}, 15)), is(Integer.valueOf(0)));
        assertThat(Integer.valueOf(Utils.bit(new byte[]{(byte) 1, (byte) 2, (byte) 3}, 16)), is(Integer.valueOf(1)));
    }

    @Test
    public void hexToBytesReturnsCorrectByteArray() {
        Assert.assertThat(Utils.hexToBytes(hex1), IsEqual.equalTo(bytes1));
        Assert.assertThat(Utils.hexToBytes(hex2), IsEqual.equalTo(bytes2));
        Assert.assertThat(Utils.hexToBytes(hex3), IsEqual.equalTo(bytes3));
    }

    @Test
    public void bytesToHexReturnsCorrectHexString() {
        Assert.assertThat(Utils.bytesToHex(bytes1), IsEqual.equalTo(hex1));
        Assert.assertThat(Utils.bytesToHex(bytes2), IsEqual.equalTo(hex2));
        Assert.assertThat(Utils.bytesToHex(bytes3), IsEqual.equalTo(hex3));
    }
}
