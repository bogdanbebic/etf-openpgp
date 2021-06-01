package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.*;

import java.io.FileInputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

public class PGPUtility {

    private static final int BUFFER_SIZE = 1 << 16;

    public static void signEncryptFile(
            OutputStream out,
            String fileName,
            PGPPublicKeyRing publicKey,
            PGPSecretKey secretKey,
            String password,
            boolean encrypt,
            boolean sign,
            boolean compress,
            boolean radix64,
            boolean isCAST5)
            throws Exception
    {

        // Initialize Bouncy Castle security provider
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        if (radix64) {
            out = new ArmoredOutputStream(out);
        }

        // ENCRYPT
        BcPGPDataEncryptorBuilder dataEncryptor;

        if (encrypt) {
            if (isCAST5) {
                dataEncryptor = new BcPGPDataEncryptorBuilder(PGPEncryptedData.CAST5);
            }
            else {
                dataEncryptor = new BcPGPDataEncryptorBuilder(PGPEncryptedData.TRIPLE_DES);
            }
            dataEncryptor.setWithIntegrityPacket(true);
            dataEncryptor.setSecureRandom(new SecureRandom());
        }
        else {
            dataEncryptor = new BcPGPDataEncryptorBuilder(PGPEncryptedData.NULL);
        }

        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);

        PGPPublicKey next = null;

        for (Iterator<PGPPublicKey> iterator = publicKey.getPublicKeys(); iterator.hasNext();) {
            next = iterator.next();
        }

        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(next));

        OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[PGPUtility.BUFFER_SIZE]);

        // COMPRESS
        PGPCompressedDataGenerator compressedDataGenerator =
                new PGPCompressedDataGenerator(compress ? PGPCompressedData.ZIP : PGPCompressedData.UNCOMPRESSED);
        OutputStream compressedOut = compressedDataGenerator.open(encryptedOut, new byte [PGPUtility.BUFFER_SIZE]);

        // SIGN
        PGPSignatureGenerator signatureGenerator = null;

        if (sign) {
            PGPPrivateKey privateKey = findPrivateKey(secretKey, password.toCharArray());
            PGPContentSignerBuilder signerBuilder = new BcPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(),
                    HashAlgorithmTags.SHA1);
            signatureGenerator = new PGPSignatureGenerator(signerBuilder);
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

            boolean firstTime = true;
            Iterator<String> it = secretKey.getPublicKey().getUserIDs();
            while (it.hasNext() && firstTime) {
                PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
                spGen.setSignerUserID(false, it.next());
                signatureGenerator.setHashedSubpackets(spGen.generate());
                // Exit the loop after the first iteration
                firstTime = false;
            }
            signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
        }

        // Initialize literal data generator
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalDataGenerator.open(
                compressedOut,
                PGPLiteralData.BINARY,
                fileName,
                new Date(),
                new byte [PGPUtility.BUFFER_SIZE] );

        // Main loop - read the "in" stream, compress, encrypt and write to the "out" stream
        FileInputStream in = new FileInputStream(fileName);
        byte[] buf = new byte[PGPUtility.BUFFER_SIZE];
        int len;
        while ((len = in.read(buf)) > 0) {
            literalOut.write(buf, 0, len);
            if (sign)
                signatureGenerator.update(buf, 0, len);
        }

        in.close();
        literalDataGenerator.close();
        // Generate the signature, compress, encrypt and write to the "out" stream
        signatureGenerator.generate().encode(compressedOut);
        compressedDataGenerator.close();
        encryptedDataGenerator.close();
        if (radix64) {
            out.close();
        }
    }

    public static PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecKey, char[] pass)
            throws PGPException
    {
        if (pgpSecKey == null) return null;

        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass);
        return pgpSecKey.extractPrivateKey(decryptor);
    }

}
