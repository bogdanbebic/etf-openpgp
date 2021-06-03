package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Optional;

public class PGPUtility {

    private static final int BUFFER_SIZE = 1 << 16;

    public static void signEncryptFile(
            String fileName,
            PGPPublicKeyRing publicKey,
            PGPSecretKeyRing secretKey,
            char[] password,
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

        OutputStream out = new FileOutputStream(fileName + ".pgp");

        if (radix64) {
            out = new ArmoredOutputStream(out);
        }

        // ENCRYPT
        BcPGPDataEncryptorBuilder dataEncryptor;
        OutputStream encryptedOut = out;
        PGPEncryptedDataGenerator encryptedDataGenerator = null;

        if (encrypt) {
            if (isCAST5) {
                dataEncryptor = new BcPGPDataEncryptorBuilder(PGPEncryptedData.CAST5);
            }
            else {
                dataEncryptor = new BcPGPDataEncryptorBuilder(PGPEncryptedData.TRIPLE_DES);
            }
            dataEncryptor.setWithIntegrityPacket(true);
            dataEncryptor.setSecureRandom(new SecureRandom());

            encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);

            PGPPublicKey next = null;

            for (Iterator<PGPPublicKey> iterator = publicKey.getPublicKeys(); iterator.hasNext();) {
                next = iterator.next();
                if (next.isEncryptionKey())
                    break;
            }

            encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(next));
            encryptedOut = encryptedDataGenerator.open(out, new byte[PGPUtility.BUFFER_SIZE]);
        }

        // COMPRESS
        PGPCompressedDataGenerator compressedDataGenerator =
                new PGPCompressedDataGenerator(compress ? PGPCompressedData.ZIP : PGPCompressedData.UNCOMPRESSED);
        OutputStream compressedOut = compressedDataGenerator.open(encryptedOut, new byte [PGPUtility.BUFFER_SIZE]);

        // SIGN
        PGPSignatureGenerator signatureGenerator = null;

        if (sign) {

            PGPSecretKey next = null;
            for (Iterator<PGPSecretKey> iterator = secretKey.getSecretKeys(); iterator.hasNext();) {
                next = iterator.next();
                if (next.isSigningKey())
                    break;
            }

            PGPPrivateKey privateKey = findPrivateKey(secretKey.getSecretKey(), password);
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
        if (sign)
            signatureGenerator.generate().encode(compressedOut);
        if (compress)
            compressedDataGenerator.close();
        if (encrypt)
            encryptedDataGenerator.close();
        out.close();
    }

    public static PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecKey, char[] pass)
            throws PGPException
    {
        if (pgpSecKey == null) return null;

        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(
                new BcPGPDigestCalculatorProvider()).build(pass);
        return pgpSecKey.extractPrivateKey(decryptor);
    }

    public static Optional<String> decryptAndVerify(
            String filename,
            char[] passphrase)
            throws IOException, PGPException
    {
        PGPSecretKeyRingCollection secretKeyCollection = new PGPSecretKeyRingCollection(Menu.privateKeyRingTableModel.getPrivateKeys());

        OutputStream fOut = new FileOutputStream("decrypted.txt");

        PGPObjectFactory pgpF = new PGPObjectFactory(
                PGPUtil.getDecoderStream(new FileInputStream(filename)),
                new BcKeyFingerprintCalculator());

        PGPEncryptedDataList enc;

        Object o = pgpF.nextObject();

        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;

            Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPEncryptedData pbe = null;

            while (sKey == null && it.hasNext()) {
                pbe = it.next();

                try {
                    sKey = findPrivateKey(secretKeyCollection.getSecretKey(((PGPPublicKeyEncryptedData)pbe).getKeyID()), passphrase);
                } catch (Exception ignored) {

                }
            }

            if (sKey == null) {
                return Optional.empty();
            }

            InputStream clear = ((PGPPublicKeyEncryptedData)pbe).getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));

            PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

            Object msgDecryption;

            PGPOnePassSignatureList onePassSignatureList = null;
            PGPSignatureList signatureList = null;
            PGPCompressedData compressedData;

            msgDecryption = plainFact.nextObject();
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();

            while (msgDecryption != null) {

                if (msgDecryption instanceof PGPCompressedData) {
                    compressedData = (PGPCompressedData) msgDecryption;
                    plainFact = new PGPObjectFactory(compressedData.getDataStream(), new BcKeyFingerprintCalculator());
                    msgDecryption = plainFact.nextObject();
                }

                if (msgDecryption instanceof PGPLiteralData) {

                    Streams.pipeAll(((PGPLiteralData) msgDecryption).getInputStream(), outStream);
                }
                if (msgDecryption instanceof PGPSignatureList) {
                    signatureList = (PGPSignatureList) msgDecryption;
                }
                if (msgDecryption instanceof PGPOnePassSignatureList) {
                    onePassSignatureList = (PGPOnePassSignatureList) msgDecryption;
                }

                msgDecryption = plainFact.nextObject();
            }

            outStream.close();
            fOut.write(outStream.toByteArray());
            fOut.close();

        }



        return Optional.of("YO MAMA IS VERIFIED .l.");
    }

//    public static void decryptFile(InputStream in, OutputStream out, InputStream keyIn, char[] passwd)
//            throws Exception
//    {
//        Security.addProvider(new BouncyCastleProvider());
//
//        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
//
//        PGPObjectFactory pgpF = new PGPObjectFactory(in);
//        PGPEncryptedDataList enc;
//
//        Object o = pgpF.nextObject();
//        //
//        // the first object might be a PGP marker packet.
//        //
//        if (o instanceof  PGPEncryptedDataList) {
//            enc = (PGPEncryptedDataList) o;
//        } else {
//            enc = (PGPEncryptedDataList) pgpF.nextObject();
//        }
//
//        //
//        // find the secret key
//        //
//        Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
//        PGPPrivateKey sKey = null;
//        PGPPublicKeyEncryptedData pbe = null;
//
//        while (sKey == null && it.hasNext()) {
//            pbe = it.next();
//
//            sKey = findPrivateKey(keyIn, pbe.getKeyID(), passwd);
//        }
//
//        if (sKey == null) {
//            throw new IllegalArgumentException("Secret key for message not found.");
//        }
//
//        InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
//
//        PGPObjectFactory plainFact = new PGPObjectFactory(clear);
//
//        Object message = plainFact.nextObject();
//
//        if (message instanceof  PGPCompressedData) {
//            PGPCompressedData cData = (PGPCompressedData) message;
//            PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());
//
//            message = pgpFact.nextObject();
//        }
//
//        if (message instanceof  PGPLiteralData) {
//            PGPLiteralData ld = (PGPLiteralData) message;
//
//            InputStream unc = ld.getInputStream();
//            int ch;
//
//            while ((ch = unc.read()) >= 0) {
//                out.write(ch);
//            }
//        } else if (message instanceof  PGPOnePassSignatureList) {
//            throw new PGPException("Encrypted message contains a signed message - not literal data.");
//        } else {
//            throw new PGPException("Message is not a simple encrypted file - type unknown.");
//        }
//
//        if (pbe.isIntegrityProtected()) {
//            if (!pbe.verify()) {
//                throw new PGPException("Message failed integrity check");
//            }
//        }
//    }
//
//    public static boolean verifyFile(
//            InputStream in,
//            InputStream keyIn,
//            String extractContentFile)
//            throws Exception
//    {
//        in = PGPUtil.getDecoderStream(in);
//
//        PGPObjectFactory pgpFact = new PGPObjectFactory(in);
//        PGPCompressedData c1 = (PGPCompressedData)pgpFact.nextObject();
//
//        pgpFact = new PGPObjectFactory(c1.getDataStream());
//
//        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)pgpFact.nextObject();
//
//        PGPOnePassSignature ops = p1.get(0);
//
//        PGPLiteralData p2 = (PGPLiteralData)pgpFact.nextObject();
//
//        InputStream dIn = p2.getInputStream();
//
//        IOUtils.copy(dIn, new FileOutputStream(extractContentFile));
//
//        int ch;
//        PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
//
//        PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
//
//        FileOutputStream out = new FileOutputStream(p2.getFileName());
//
//        ops.init(new BcPGPContentVerifierBuilderProvider(), key);
//
//        while ((ch = dIn.read()) >= 0)
//        {
//            ops.update((byte)ch);
//            out.write(ch);
//        }
//
//        out.close();
//
//        PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();
//        return ops.verify(p3.get(0));
//    }

}
