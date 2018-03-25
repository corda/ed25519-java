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

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class Ed25519TestVectors {
    public static class TestTuple {
        static int numCases;
        public final int caseNum;
        @NotNull
        public final byte[] seed;
        @NotNull
        public final byte[] pk;
        @NotNull
        public final byte[] message;
        @NotNull
        public final byte[] sig;

        TestTuple(final String line) {
            caseNum = ++numCases;
            @NotNull final String[] x = line.split(":");
            seed = Utils.hexToBytes(x[0].substring(0, 64));
            pk = Utils.hexToBytes(x[1]);
            message = Utils.hexToBytes(x[2]);
            sig = Utils.hexToBytes(x[3].substring(0, 128));
        }
    }

    public static final Collection<TestTuple> testCases = getTestData("test.data");

    @NotNull
    private static Collection<TestTuple> getTestData(final String fileName) {
        @NotNull final Collection<TestTuple> testCases = new ArrayList<>();
        @Nullable BufferedReader file = null;
        try {
            final InputStream is = Ed25519TestVectors.class.getResourceAsStream(fileName);
            if (null == is)
                throw new IOException("Resource not found: " + fileName);
            file = new BufferedReader(new InputStreamReader(is));

            while (true) {    String line= file.readLine();
                if (!(null != (line ))) break;
                testCases.add(new TestTuple(line));
            }
        } catch (@NotNull final IOException e) {
            e.printStackTrace();
        } finally {
            if (null != file) try { file.close(); } catch (@NotNull final IOException e) {}
        }
        return testCases;
    }
}
