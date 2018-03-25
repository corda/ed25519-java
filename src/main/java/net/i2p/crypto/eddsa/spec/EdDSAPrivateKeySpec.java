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
package net.i2p.crypto.eddsa.spec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import net.i2p.crypto.eddsa.math.GroupElement;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * @author str4d
 *
 */
public class EdDSAPrivateKeySpec implements KeySpec {
    @Nullable
    public final byte[] seed;
    public final byte[] hashOfTheSeed;
    public final byte[] privateKey;
    public final GroupElement groupElement;
    private final EdDSAParameterSpec spec;

    /**
     *  @param seed the private key
     *  @param spec the parameter specification for this key
     *  @throws IllegalArgumentException if seed length is wrong or hash algorithm is unsupported
     */
    public EdDSAPrivateKeySpec(final byte[] seed, final EdDSAParameterSpec spec) {
        assert seed.length == spec.curve.getEdDSAFiniteField().getb() / 8 : "seed length is wrong";

        this.spec = spec;
        this.seed = seed.clone();

        try {
            final MessageDigest hash = MessageDigest.getInstance(spec.hashAlgo);
            final int b = spec.curve.getEdDSAFiniteField().getb();

            // H(k)
            hashOfTheSeed = hash.digest(seed);

            /*a = BigInteger.valueOf(2).pow(b-2);
            for (int i=3;i<(b-2);i++) {
                a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(Utils.bit(h,i))));
            }*/
            // Saves ~0.4ms per key when running signing tests.
            // TODO: are these bitflips the same for any hash function?
            hashOfTheSeed[0] = (byte) (hashOfTheSeed[0] & 248);
            hashOfTheSeed[(b / 8) - 1] = (byte) (hashOfTheSeed[(b / 8) - 1] & 63);
            hashOfTheSeed[(b / 8) - 1] = (byte) (hashOfTheSeed[(b / 8) - 1] | 64);
            privateKey = Arrays.copyOfRange(hashOfTheSeed, 0, b/8);

            groupElement = spec.groupElement.scalarMultiply(privateKey);
        } catch (@NotNull final NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm");
        }
    }

    /**
     *  Initialize directly from the hash.
     *  getSeed() will return null if this constructor is used.
     *
     *  @param spec the parameter specification for this key
     *  @param hashOfTheSeed the private key
     *  @throws IllegalArgumentException if hash length is wrong
     *  @since 0.1.1
     */
    public EdDSAPrivateKeySpec(final EdDSAParameterSpec spec, final byte[] hashOfTheSeed) {
        assert hashOfTheSeed.length == spec.curve.getEdDSAFiniteField().getb() / 4 : "hash length is wrong";

	this.seed = null;
        //noinspection AssignmentOrReturnOfFieldWithMutableType
        this.hashOfTheSeed = hashOfTheSeed/*.clone()*/;//TODO how is cloning the array of a hash possibly breaking a test?
	this.spec = spec;
        final int b = spec.curve.getEdDSAFiniteField().getb();

        hashOfTheSeed[0] = (byte) (hashOfTheSeed[0] & 248);
        hashOfTheSeed[(b / 8) - 1] = (byte) (hashOfTheSeed[(b / 8) - 1] & 63);
        hashOfTheSeed[(b / 8) - 1] = (byte) (hashOfTheSeed[(b / 8) - 1] | 64);
        privateKey = Arrays.copyOfRange(hashOfTheSeed, 0, b/8);

        groupElement = spec.groupElement.scalarMultiply(privateKey);
    }

    public EdDSAPrivateKeySpec(final byte[] seed, final byte[] hashOfTheSeed, final byte[] privateKey, final GroupElement groupElement, final EdDSAParameterSpec spec) {
        this.seed = seed.clone();
        this.hashOfTheSeed = hashOfTheSeed.clone();
        this.privateKey = privateKey.clone();
        this.groupElement = groupElement;
        this.spec = spec;
    }

    public EdDSAParameterSpec getParams() {
        return spec;
    }
}
