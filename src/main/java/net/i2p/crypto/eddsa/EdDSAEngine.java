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

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.IntStream;

import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.math.ScalarOps;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import sun.security.x509.X509Key;

/**
 * Signing and verification for EdDSA.
 *<p>
 * The EdDSA sign and verify algorithms do not interact well with
 * the Java Signature API, as one or more update() methods must be
 * called before sign() or verify(). Using the standard API,
 * this implementation must copy and buffer all data passed in
 * via update().
 *</p><p>
 * This implementation offers two ways to avoid this copying,
 * but only if all data to be signed or verified is available
 * in a single byte array.
 *</p><p>
 *Option 1:
 *</p><ol>
 *<li>Call initSign() or initVerify() as usual.
 *</li><li>Call setParameter(ONE_SHOT_MODE)
 *</li><li>Call update(byte[]) or update(byte[], int, int) exactly once
 *</li><li>Call sign() or verify() as usual.
 *</li><li>If doing additional one-shot signs or verifies with this object, you must
 *         call setParameter(ONE_SHOT_MODE) each time
 *</li></ol>
 *
 *<p>
 *Option 2:
 *</p><ol>
 *<li>Call initSign() or initVerify() as usual.
 *</li><li>Call one of the signOneShot() or verifyOneShot() methods.
 *</li><li>If doing additional one-shot signs or verifies with this object,
 *         just call signOneShot() or verifyOneShot() again.
 *</li></ol>
 *
 * @author str4d
 *
 */
public final class EdDSAEngine extends Signature {
    public static final String SIGNATURE_ALGORITHM = "NONEwithEdDSA";
    public static final byte[] EMPTY = new byte[0];

    private MessageDigest digest;
    private ByteArrayOutputStream baos;
    private EdDSAKey key;
    public boolean oneShotMode;
    @Nullable
    public byte[] oneShotBytes;
    public int oneShotOffset;
    public int oneShotLength;

    /**
     *  To efficiently sign or verify data in one shot, pass this to setParameters()
     *  after initSign() or initVerify() but BEFORE THE FIRST AND ONLY
     *  update(data) or update(data, off, len). The data reference will be saved
     *  and then used in sign() or verify() without copying the data.
     *  Violate these rules and you will get a SignatureException.
     */
    public static final AlgorithmParameterSpec ONE_SHOT_MODE = new OneShotSpec();

    public static class OneShotSpec implements AlgorithmParameterSpec {}

    /**
     * No specific EdDSA-internal hash requested, allows any EdDSA key.
     */
    public EdDSAEngine() {
        super(SIGNATURE_ALGORITHM);
    }

    /**
     * Specific EdDSA-internal hash requested, only matching keys will be allowed.
     * @param digest the hash algorithm that keys must have to sign or verify.
     */
    public EdDSAEngine(final MessageDigest digest) {
        this();
        this.digest = digest;
    }

    public void reset() {
        if (null != digest)
            digest.reset();
        if (null != baos)
            baos.reset();
        oneShotMode = false;
        oneShotBytes = null;
    }

    @Override
    protected void engineInitSign(final PrivateKey privateKey) throws InvalidKeyException {
        reset();
        if (privateKey instanceof EdDSAPrivateKey) {
            @NotNull final EdDSAPrivateKey privKey = (EdDSAPrivateKey) privateKey;
            key = privKey;

            if (null == digest) {
                // Instantiate the digest from the key parameters
                try {
                    digest = MessageDigest.getInstance(key.getEdDSAParameterSpec().hashAlgo);
                } catch (@NotNull final NoSuchAlgorithmException e) {
                    throw new InvalidKeyException("cannot get required digest " + key.getEdDSAParameterSpec().hashAlgo + " for private key.");
                }
            } else
                assert key.getEdDSAParameterSpec().hashAlgo.equals(digest.getAlgorithm()) : "Key hash algorithm does not match chosen digest";
            digestInitSign(privKey);
        } else {
            throw new InvalidKeyException("cannot identify EdDSA private key: " + privateKey.getClass());
        }
    }

    public void digestInitSign(final EdDSAPrivateKey privKey) {
        // Preparing for hash
        // r = H(h_b,...,h_2b-1,M)
        final int b = privKey.getEdDSAParameterSpec().curve.getEdDSAFiniteField().getb();
        digest.update(privKey.getHashOfTheSeed(), b/8, b/4 - b/8);
    }

    @Override
    protected void engineInitVerify(final PublicKey publicKey) throws InvalidKeyException {
        reset();
        if (publicKey instanceof EdDSAPublicKey) {
            key = (EdDSAPublicKey) publicKey;

            if (null == digest) {
                // Instantiate the digest from the key parameters
                try {
                    digest = MessageDigest.getInstance(key.getEdDSAParameterSpec().hashAlgo);
                } catch (@NotNull final NoSuchAlgorithmException e) {
                    throw new InvalidKeyException("cannot get required digest " + key.getEdDSAParameterSpec().hashAlgo + " for private key.");
                }
            } else
                assert key.getEdDSAParameterSpec().hashAlgo.equals(digest.getAlgorithm()) : "Key hash algorithm does not match chosen digest";
        } else if (publicKey instanceof X509Key) {
            // X509Certificate will sometimes contain an X509Key rather than the EdDSAPublicKey itself; the contained
            // key is valid but needs to be instanced as an EdDSAPublicKey before it can be used.
            @NotNull final EdDSAPublicKey parsedPublicKey;
            try {
                parsedPublicKey = new EdDSAPublicKey(new X509EncodedKeySpec(publicKey.getEncoded()));
            } catch (@NotNull final InvalidKeySpecException ex) {
                throw new InvalidKeyException("cannot handle X.509 EdDSA public key: " + publicKey.getAlgorithm());
            }
            engineInitVerify(parsedPublicKey);
        } else {
            throw new InvalidKeyException("cannot identify EdDSA public key: " + publicKey.getClass());
        }
    }

    /**
     * @throws SignatureException if in one-shot mode
     */
    @Override
    protected void engineUpdate(final byte b) {
        assert !oneShotMode : "unsupported in one-shot mode";
        if (null == baos)
            baos = new ByteArrayOutputStream(256);
        baos.write((int) b);
    }

    /**
     * @throws SignatureException if one-shot rules are violated
     */
    @Override
    protected void engineUpdate(@NotNull final byte[] b, final int off, final int len)
            throws SignatureException {
        if (oneShotMode) {
            if (null == oneShotBytes) {
                oneShotBytes = b.clone();
                oneShotOffset = off;
                oneShotLength = len;
            } else throw new SignatureException("update() already called");
        } else {
            if (null == baos)
                baos = new ByteArrayOutputStream(256);
            baos.write(b, off, len);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            return x_engineSign();
        } finally {
            reset();
            // must leave the object ready to sign again with
            // the same key, as required by the API
            @NotNull final EdDSAPrivateKey privKey = (EdDSAPrivateKey) key;
            digestInitSign(privKey);
        }
    }

    public byte[] x_engineSign() {
        @NotNull final Curve curve = key.getEdDSAParameterSpec().curve;
        final ScalarOps sc = key.getEdDSAParameterSpec().scalarOps;
        final byte[] a = ((EdDSAPrivateKey) key).getPrivateKey();

        @Nullable final byte[] message;
        final int offset;
        final int length;
        if (oneShotMode) {
            Objects.requireNonNull(oneShotBytes);
            message = oneShotBytes;
            offset = oneShotOffset;
            length = oneShotLength;
        } else {
            message = null == baos ? EMPTY : baos.toByteArray();
            offset = 0;
            length = message.length;
        }
        // r = H(h_b,...,h_2b-1,M)
        digest.update(message, offset, length);
        byte[] r = digest.digest();

        // r mod l
        // Reduces r from 64 bytes to 32 bytes
        r = sc.reduce(r);

        // R = rB
        final GroupElement R = key.getEdDSAParameterSpec().groupElement.scalarMultiply(r);
        final byte[] Rbyte = R.toByteArray();

        // S = (r + H(Rbar,Abar,M)*a) mod l
        digest.update(Rbyte);
        digest.update(((EdDSAPrivateKey) key).getaByte());
        digest.update(message, offset, length);
        byte[] h = digest.digest();
        h = sc.reduce(h);
        final byte[] S = sc.multiplyAndAdd(h, a, r);

        // R+S
        final int b = curve.getEdDSAFiniteField().getb();
        @NotNull final ByteBuffer out = ByteBuffer.allocate(b/4);
        out.put(Rbyte).put(S);
        return out.array();
    }

    @Override
    protected boolean engineVerify(@NotNull final byte[] sigBytes) throws SignatureException {
        try {
            return x_engineVerify(sigBytes);
        } finally {
            reset();
        }
    }

    public boolean x_engineVerify(final byte[] sigBytes) {
        @NotNull final Curve curve = key.getEdDSAParameterSpec().curve;
        final int b = curve.getEdDSAFiniteField().getb();
        assert sigBytes.length == b / 4 : "signature length is wrong";

        // R is first b/8 bytes of sigBytes, S is second b/8 bytes
        digest.update(sigBytes, 0, b/8);
        digest.update(((EdDSAPublicKey) key).getaByte());
        // h = H(Rbar,Abar,M)
        @Nullable final byte[] message;
        final int offset;
        final int length;
        if (oneShotMode) {
            Objects.requireNonNull(oneShotBytes);
            message = oneShotBytes;
            offset = oneShotOffset;
            length = oneShotLength;
        } else {
            message = null == baos ? EMPTY : baos.toByteArray();
            offset = 0;
            length = message.length;
        }
        digest.update(message, offset, length);
        byte[] h = digest.digest();

        // h mod l
        h = key.getEdDSAParameterSpec().scalarOps.reduce(h);

        @NotNull final byte[] Sbyte = Arrays.copyOfRange(sigBytes, b/8, b/4);
        // R = SB - H(Rbar,Abar,M)A
        final GroupElement R = key.getEdDSAParameterSpec().groupElement.doubleScalarMultiplyVariableTime(
                ((EdDSAPublicKey) key).getaNeg(), h, Sbyte);

        // Variable time. This should be okay, because there are no secret
        // values used anywhere in verification.
        final byte[] Rcalc = R.toByteArray();
        final int bound = Rcalc.length;
        return IntStream.range(0, bound).noneMatch(i -> Rcalc[i] != sigBytes[i]);
    }

    /**
     *  To efficiently sign all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data)
     *  sig = sign()
     *</pre>
     *
     * @param data the message to be signed
     * @return the signature
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public byte[] signOneShot(@NotNull final byte[] data) throws SignatureException {
        return signOneShot(data, 0, data.length);
    }

    /**
     *  To efficiently sign all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data, off, len)
     *  sig = sign()
     *</pre>
     *
     * @param data byte array containing the message to be signed
     * @param off the start of the message inside data
     * @param len the length of the message
     * @return the signature
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public byte[] signOneShot(@NotNull final byte[] data, final int off, final int len) throws SignatureException {
        oneShotMode = true;
        update(data, off, len);
        return sign();
    }

    /**
     *  To efficiently verify all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data)
     *  ok = verify(signature)
     *</pre>
     *
     * @param data the message that was signed
     * @param signature of the message
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public boolean verifyOneShot(@NotNull final byte[] data, @NotNull final byte[] signature) throws SignatureException {
        return verifyOneShot(data, 0, data.length, signature, 0, signature.length);
    }

    /**
     *  To efficiently verify all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data, off, len)
     *  ok = verify(signature)
     *</pre>
     *
     * @param data byte array containing the message that was signed
     * @param off the start of the message inside data
     * @param len the length of the message
     * @param signature of the message
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public boolean verifyOneShot(@NotNull final byte[] data, final int off, final int len, @NotNull final byte[] signature) throws SignatureException {
        return verifyOneShot(data, off, len, signature, 0, signature.length);
    }

    /**
     *  To efficiently verify all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data)
     *  ok = verify(signature, sigoff, siglen)
     *</pre>
     *
     * @param data the message that was signed
     * @param signature byte array containing the signature
     * @param sigoff the start of the signature
     * @param siglen the length of the signature
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public boolean verifyOneShot(@NotNull final byte[] data, @NotNull final byte[] signature, final int sigoff, final int siglen) throws SignatureException {
        return verifyOneShot(data, 0, data.length, signature, sigoff, siglen);
    }

    /**
     *  To efficiently verify all the data in one shot, if it is available,
     *  use this method, which will avoid copying the data.
     *
     * Same as:
     *<pre>
     *  setParameter(ONE_SHOT_MODE)
     *  update(data, off, len)
     *  ok = verify(signature, sigoff, siglen)
     *</pre>
     *
     * @param data byte array containing the message that was signed
     * @param off the start of the message inside data
     * @param len the length of the message
     * @param signature byte array containing the signature
     * @param sigoff the start of the signature
     * @param siglen the length of the signature
     * @return true if the signature is valid, false otherwise
     * @throws SignatureException if update() already called
     * @see #ONE_SHOT_MODE
     */
    public boolean verifyOneShot(@NotNull final byte[] data, final int off, final int len, @NotNull final byte[] signature, final int sigoff, final int siglen) throws SignatureException {
        oneShotMode = true;
        update(data, off, len);
        return verify(signature, sigoff, siglen);
    }

    /**
     * @throws InvalidAlgorithmParameterException if spec is ONE_SHOT_MODE and update() already called
     * @see #ONE_SHOT_MODE
     */
    @Override
    protected void engineSetParameter(final AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
        if (spec.equals(ONE_SHOT_MODE)) {
            assert null == oneShotBytes && (null == baos || 0 >= baos.size()) : "update() already called";
            oneShotMode = true;
        } else {
            super.engineSetParameter(spec);
        }
    }

    /**
     * @deprecated
     */
    @Override
    protected void engineSetParameter(final String param, final Object value) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    @NotNull
    @Override
    protected Object engineGetParameter(final String param) {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }
}
