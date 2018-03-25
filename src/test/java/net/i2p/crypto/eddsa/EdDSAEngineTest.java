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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Iterator;

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import org.jetbrains.annotations.NotNull;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import sun.security.util.DerValue;
import sun.security.x509.X509Key;

/**
 * @author str4d
 *
 */
public class EdDSAEngineTest {
    private static final byte[] TEST_SEED = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] TEST_PK = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    private static final byte[] TEST_MSG = "This is a secret message".getBytes(Charset.forName("UTF-8"));
    private static final byte[] TEST_MSG_SIG = Utils.hexToBytes("94825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f");

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    @Test
    public void testSign() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
        @NotNull final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));

        for (@NotNull Iterator<Ed25519TestVectors.TestTuple> iterator = Ed25519TestVectors.testCases.iterator(); iterator.hasNext(); ) {
            Ed25519TestVectors.TestTuple testCase = iterator.next();
            @NotNull final EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(testCase.seed, spec);
            @NotNull final PrivateKey sKey = new EdDSAPrivateKey(privKey);
            sgr.initSign(sKey);

            sgr.update(testCase.message);

            assertThat("Test case " + testCase.caseNum + " failed",
                    sgr.sign(), is(equalTo(testCase.sig)));
        }
    }

    @Test
    public void testVerify() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
        @NotNull final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));
        for (@NotNull Iterator<Ed25519TestVectors.TestTuple> iterator = Ed25519TestVectors.testCases.iterator(); iterator.hasNext(); ) {
            Ed25519TestVectors.TestTuple testCase = iterator.next();
            @NotNull final EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(testCase.pk, spec);
            @NotNull final PublicKey vKey = new EdDSAPublicKey(pubKey);
            sgr.initVerify(vKey);

            sgr.update(testCase.message);

            assertThat("Test case " + testCase.caseNum + " failed",
                    Boolean.valueOf(sgr.verify(testCase.sig)), is(Boolean.TRUE));
        }
    }

    /**
     * Checks that a wrong-length signature throws an IAE.
     */
    @Test
    public void testVerifyWrongSigLength() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
        @NotNull final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));
        @NotNull final EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(TEST_PK, spec);
        @NotNull final PublicKey vKey = new EdDSAPublicKey(pubKey);
        sgr.initVerify(vKey);

        sgr.update(TEST_MSG);

        exception.expect(AssertionError.class);
        exception.expectMessage("signature length is wrong");
        sgr.verify(new byte[] {(byte) 0});
    }

    @Test
    public void testSignResetsForReuse() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        @NotNull final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));
        @NotNull final EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(TEST_SEED, spec);
        @NotNull final PrivateKey sKey = new EdDSAPrivateKey(privKey);
        sgr.initSign(sKey);

        // First usage
        sgr.update(new byte[] {(byte) 0});
        sgr.sign();

        // Second usage
        sgr.update(TEST_MSG);
        assertThat("Second sign failed", sgr.sign(), is(equalTo(TEST_MSG_SIG)));
    }

    @Test
    public void testVerifyResetsForReuse() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        @NotNull final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));
        @NotNull final EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(TEST_PK, spec);
        @NotNull final PublicKey vKey = new EdDSAPublicKey(pubKey);
        sgr.initVerify(vKey);

        // First usage
        sgr.update(new byte[] {(byte) 0});
        sgr.verify(TEST_MSG_SIG);

        // Second usage
        sgr.update(TEST_MSG);
        assertThat("Second verify failed", Boolean.valueOf(sgr.verify(TEST_MSG_SIG)), is(Boolean.TRUE));
    }

    @Test
    public void testSignOneShotMode() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        @NotNull final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));
        @NotNull final EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(TEST_SEED, spec);
        @NotNull final PrivateKey sKey = new EdDSAPrivateKey(privKey);
        sgr.initSign(sKey);
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);

        sgr.update(TEST_MSG);

        assertThat("One-shot mode sign failed", sgr.sign(), is(equalTo(TEST_MSG_SIG)));
    }

    @Test
    public void testVerifyOneShotMode() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        @NotNull final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));
        @NotNull final EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(TEST_PK, spec);
        @NotNull final PublicKey vKey = new EdDSAPublicKey(pubKey);
        sgr.initVerify(vKey);
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);

        sgr.update(TEST_MSG);

        assertThat("One-shot mode verify failed", Boolean.valueOf(sgr.verify(TEST_MSG_SIG)), is(Boolean.TRUE));
    }

    @Test
    public void testSignOneShotModeMultipleUpdates() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        @NotNull final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));
        @NotNull final EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(TEST_SEED, spec);
        @NotNull final PrivateKey sKey = new EdDSAPrivateKey(privKey);
        sgr.initSign(sKey);
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);

        sgr.update(TEST_MSG);

        exception.expect(SignatureException.class);
        exception.expectMessage("update() already called");
        sgr.update(TEST_MSG);
    }

    @Test
    public void testVerifyOneShotModeMultipleUpdates() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        @NotNull final EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(TEST_PK, spec);
        @NotNull final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));
        @NotNull final PublicKey vKey = new EdDSAPublicKey(pubKey);
        sgr.initVerify(vKey);
        sgr.setParameter(EdDSAEngine.ONE_SHOT_MODE);

        sgr.update(TEST_MSG);

        exception.expect(SignatureException.class);
        exception.expectMessage("update() already called");
        sgr.update(TEST_MSG);
    }

    @Test
    public void testSignOneShot() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        @NotNull final EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(TEST_SEED, spec);
        @NotNull final EdDSAEngine sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));
        @NotNull final PrivateKey sKey = new EdDSAPrivateKey(privKey);
        sgr.initSign(sKey);

        assertThat("signOneShot() failed", sgr.signOneShot(TEST_MSG), is(equalTo(TEST_MSG_SIG)));
    }

    @Test
    public void testVerifyOneShot() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        @NotNull final EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(TEST_PK, spec);
        @NotNull final EdDSAEngine sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));
        @NotNull final PublicKey vKey = new EdDSAPublicKey(pubKey);
        sgr.initVerify(vKey);

        assertThat("verifyOneShot() failed", Boolean.valueOf(sgr.verifyOneShot(TEST_MSG, TEST_MSG_SIG)), is(Boolean.TRUE));
    }

    @Test
    public void testVerifyX509PublicKeyInfo() throws Exception {
        final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
        @NotNull final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.hashAlgo));
        for (@NotNull Iterator<Ed25519TestVectors.TestTuple> iterator = Ed25519TestVectors.testCases.iterator(); iterator.hasNext(); ) {
            Ed25519TestVectors.TestTuple testCase = iterator.next();
            @NotNull final EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(testCase.pk, spec);
            @NotNull final PublicKey vKey = new EdDSAPublicKey(pubKey);
            final byte[] encoded = vKey.getEncoded();
            @NotNull final DerValue derValue = new DerValue(encoded);
            final PublicKey x509Key = X509Key.parse(derValue);
            sgr.initVerify(x509Key);

            sgr.update(testCase.message);

            assertThat("Test case " + testCase.caseNum + " failed",
                    Boolean.valueOf(sgr.verify(testCase.sig)), is(Boolean.TRUE));
        }
    }
}
