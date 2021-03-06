package etf.openpgp.bb170011dku170228d;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

/**
 * Class encapsulating RSA key generation
 */
public class RsaGeneration {

    /**
     * Generates RSA key pair and adds it to the Menu key ring table
     * @param keySize size of the generated key pair
     * @param id of the entity which owns the key
     * @param passphrase for the generated secret key
     */
    public static void generateKey(int keySize, String id, char []passphrase) {
        try {
            PGPKeyRingGenerator krGen = generateKeyRingGenerator(keySize, id, passphrase);
            PGPPublicKeyRing pkr = krGen.generatePublicKeyRing();
            PGPSecretKeyRing skr = krGen.generateSecretKeyRing();
            Menu.privateKeyRingTableModel.add(new PrivateKeyRingBean(pkr, skr));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PGPKeyRingGenerator generateKeyRingGenerator(int keySize, String id, char[] pass) throws Exception
    {
        // This object generates individual key-pairs.
        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();

        // Boilerplate RSA parameters, no need to change anything
        // except for the RSA key-size (2048). You can use whatever
        // key-size makes sense for you -- 4096, etc.
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), keySize, 12));

        // First create the master (signing) key with the generator.
        PGPKeyPair rsaKpSign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
        // Then an encryption subkey.
        PGPKeyPair rsaKpEnc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

        // Add a self-signature on the id
        PGPSignatureSubpacketGenerator signHashGen = new PGPSignatureSubpacketGenerator();

        // Add signed metadata on the signature.
        // 1) Declare its purpose
        signHashGen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        // 2) Set preferences for secondary crypto algorithms to use
        //    when sending messages to this key.
        signHashGen.setPreferredSymmetricAlgorithms(false, new int[] {
                SymmetricKeyAlgorithmTags.AES_256,
                SymmetricKeyAlgorithmTags.AES_192,
                SymmetricKeyAlgorithmTags.AES_128,
        });
        signHashGen.setPreferredHashAlgorithms(false, new int[] {
                HashAlgorithmTags.SHA256,
                HashAlgorithmTags.SHA1,
                HashAlgorithmTags.SHA384,
                HashAlgorithmTags.SHA512,
                HashAlgorithmTags.SHA224,
        });
        // 3) Request senders add additional checksums to the
        //    message (useful when verifying unsigned messages.)
        signHashGen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        // Create a signature on the encryption subkey.
        PGPSignatureSubpacketGenerator encHashGen = new PGPSignatureSubpacketGenerator();
        // Add metadata to declare its purpose
        encHashGen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        // Objects used to encrypt the secret key.
        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

        // bcpg 1.48 exposes this API that includes s2k-count. Earlier
        // versions use a default of 0x60.
        // Note: s2k-count is a number between 0 and 0xff that controls the
        // number of times to iterate the password hash before use. More
        // iterations are useful against offline attacks, as it takes more
        // time to check each password. The actual number of iterations is
        // rather complex, and also depends on the hash function in use.
        // Refer to Section 3.7.1.3 in rfc4880.txt. Bigger numbers give
        // you more iterations.  As a rough rule of thumb, when using
        // SHA256 as the hashing function, 0x10 gives you about 64
        // iterations, 0x20 about 128, 0x30 about 256 and so on till 0xf0,
        // or about 1 million iterations. The maximum you can go to is
        // 0xff, or about 2 million iterations.  I'll use 0xc0 as a
        // default -- about 130,000 iterations.
        final int s2kCount = 0xc0;
        PBESecretKeyEncryptor pskEnc =
                (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, s2kCount)).build(pass);

        // Finally, create the keyring itself. The constructor
        // takes parameters that allow it to generate the self
        // signature.
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                rsaKpSign,
                id,
                sha1Calc,
                signHashGen.generate(),
                null,
                new BcPGPContentSignerBuilder(rsaKpSign.getPublicKey().getAlgorithm(),HashAlgorithmTags.SHA1),
                pskEnc
        );

        // Add our encryption subkey, together with its signature.
        keyRingGen.addSubKey(rsaKpEnc, encHashGen.generate(), null);
        return keyRingGen;
    }
}
