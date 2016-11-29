package com.tcmj.common.crypto;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import com.tcmj.common.lang.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.tcmj.common.crypto.AES.Defaults.DEFAULT_ITERATIONS;
import static com.tcmj.common.crypto.AES.Defaults.DEFAULT_SALT_SIZE;
import static com.tcmj.common.crypto.AES.Defaults.KEY_SIZE_128_BITS;

/**
 * Implementation of the <b>A</b>dvanced <b>E</b>ncryption <b>S</b>tandard (AES), also known as Rijndael.
 * AES is a symmetric-key algorithm, meaning the same key is used for both, encrypting and decrypting data.
 * Symmetric means that for the same input, it will always generate the same output.
 * AES was published by NIST (National Institute of Standards and Technology) as FIPS PUB 197 in November 2001.
 * AES is known as a successor of the DES algorithm.
 * <ul><li>KeySize: 128, 192 or 256 Bit</li>
 * <li>BlockSize: 128 Bit fixed</li>
 * <li>Structure: Substitution-permutation network</li></ul>
 * <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">AES on Wikipedia</a>
 * <p>
 * <b>Summary</b>
 * <ul>
 * <li>Encoding can be applied to any couple of bytes (e.g. text or file).</li>
 * <li>First you have to choose a key size (128/192/256 bit) and the amount of iterations.and pass it to the constructor. </li>
 * <li>Encrypting with 192 or 256 bits needs the installation of 'JCE unlimited Strength Policy Files'</li>
 * <li>The empty constructor defaults to a key size of 128 bits and a default amount of password iterations</li>
 * <li>There's a unofficial way to get over the key size limitation by using {@link Crypto#removeCryptographyRestrictions()}</li>
 * <li>The key will be created using a password and a salt and a predefined number of iterations</li>
 * <li>Encryption also needs a so called initialisation vector (IV)</li>
 * <li>The IV will be created randomly or you can set it as a parameter on the encryptAndMerge method</li>
 * <li>The result of encryption is a byte array consisting of the salt, iv and the cipher bytes</li>
 * <li>The recipient needs to know the password, the salt, the amount of iterations, the IV and of course the encrypted bytes</li>
 * <li>The recipient generates the key in exactly the same way using the same password, salt and iteration amount</li>
 * </ul>
 * <p>
 * see
 * <pre>
 * https://www.w3.org/TR/xmlenc-core1/#sec-AES-GCM
 * https://www.bouncycastle.org/specifications.html
 * </pre>
 * <p>
 * <p>
 * todo
 * <p>
 * <p>
 * <pre>
 * No padding
 * PKCS5/7
 * ISO10126/ISO10126-2
 * ISO7816-4/ISO9797-1
 * X9.23/X923
 * TBC
 * ZeroByte
 * withCTS (if used with ECB mode)
 * </pre>
 * <p>
 * Modes:
 * <pre>
 * ECB
 * CBC
 * OFB(n)
 * CFB(n)
 * SIC (also known as CTR)
 * OpenPGPCFB
 * CTS (equivalent to CBC/WithCTS)
 * GOFB
 * GCFB
 * CCM (AEAD)
 * EAX (AEAD)
 * GCM (AEAD)
 * OCB (AEAD)
 * </pre>
 * <p>
 * Have a look on the JUnit test for detailed examples to use this class.
 * @author tcmj - Thomas Deutsch
 * @since 2.15.8
 */
public class AESGC {

    /** slf4j Logging Framework. */
    private static final Logger LOG = LoggerFactory.getLogger(AESGC.class);
    /** Key derivation specification - changing will break existing streams! */
    private static final String KEYGEN_SPEC = "PBKDF2WithHmacSHA512";
    /** Random number algorithm used by the generate Salt and IV methods. */
    private static final String RND_NUM_ALGORITHM = "SHA1PRNG";
    /** Additional Authenticated Data (AAD). AAD is authenticated but not encrypted. */
    private static byte[] AAD = "www.tcmj.de".getBytes();
    /** Cipher transformation : AES */
    private static String CIPHER_TRANSFORM_AES = "AES";
    /** AES specification: Cipher Block Chaining Mode (CBC), Padding needed because of fixed block length */
    private final CIPHERSPEC cipherSpec;
    /** Length of the Initialization Vector in bytes. 16 bytes = 128 bit. */
    private final int AES_BLOCK_SIZE;
    /** Key factory used to create key specification objects. */
    private final SecretKeyFactory factory;
    /** Main object used for en- and decoding. */
    private final Cipher cipher;
    /** Must be 128, 192 or 256 Bit! */
    private final int keySize;
    /** We need the salt size for our concatenations! */
    private final int saltSize;
    /** Iterations used to generate the key! */
    private int pwdIterations;

    /**
     * Default constructor for {@link CIPHERSPEC#AES_CBC_PKCS5PADDING}  with {@link Defaults#KEY_SIZE_128_BITS} bit key size
     * the default salt size of {@link Defaults#DEFAULT_SALT_SIZE_CBC} and the default iterations of {@link Defaults#DEFAULT_ITERATIONS} password iterations
     */
    public AESGC() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this(CIPHERSPEC.AES_CBC_PKCS5PADDING, KEY_SIZE_128_BITS, DEFAULT_SALT_SIZE, DEFAULT_ITERATIONS);
    }

    /**
     * Default constructor for {@link CIPHERSPEC#AES_CBC_PKCS5PADDING}  with {@link Defaults#KEY_SIZE_128_BITS} bit key size and
     * the default salt size of {@link Defaults#DEFAULT_SALT_SIZE_CBC} and the default iterations of {@link Defaults#DEFAULT_ITERATIONS} password iterations
     */
    public AESGC(final int keySize, final int saltSize, final int passIterations) throws NoSuchAlgorithmException, NoSuchPaddingException {
        this(CIPHERSPEC.AES_CBC_PKCS5PADDING, keySize, saltSize, passIterations);
        //todo change
    }

    /**
     * Constructor for AES where you can define custom values.
     * @param keySize must be one of {@link Defaults#KEY_SIZE_128_BITS}, {@link Defaults#KEY_SIZE_192_BITS} or {@link Defaults#KEY_SIZE_256_BITS}
     * @param saltSize a common salt size is 16 (bytes)
     * @param passIterations the password iterations used by the AES algorithm. A high value decreases performance.
     */
    public AESGC(final CIPHERSPEC cipherSpec, final int keySize, final int saltSize, final int passIterations) throws NoSuchAlgorithmException, NoSuchPaddingException {
        Objects.ensure(keySize == 128 || keySize == 192 || keySize == 256, "AES key size must be 128, 192 or 256 (bits)");
        this.keySize = keySize;
        this.saltSize = Objects.nonZero(saltSize, "Salt size must be > 0 (bytes)!");
        this.pwdIterations = Objects.nonZero(passIterations, "Password iterations must be > 0!");
        factory = SecretKeyFactory.getInstance(KEYGEN_SPEC);
        this.cipherSpec = cipherSpec;
        cipher = Cipher.getInstance(this.cipherSpec.getSpec());
        AES_BLOCK_SIZE = this.cipherSpec.getIvBlockSize();
    }

    /**
     * Additional Authenticated Data (AAD).
     * AAD is authenticated but not encrypted.
     * @return the current AAD set.
     */
    public static byte[] getAAD() {
        return AAD;
    }

    /**
     * Additional Authenticated Data (AAD).
     * AAD is authenticated but not encrypted.
     * @param AAD the AAD to set which will be used for all encodings/decodings.
     */
    public static void setAAD(byte[] AAD) {
        AESGC.AAD = AAD;
    }

    /**
     * Checks the java installation for the actually allowed key size for AES depending on the installed jurisdiction policy files (JCE).
     * @param sizeToCheck should be one of the allowed AES key bit sizes {@link Defaults#KEY_SIZE_128_BITS}, {@link Defaults#KEY_SIZE_192_BITS} or {@link Defaults#KEY_SIZE_256_BITS}
     */
    public static boolean isKeySizeAllowed(int sizeToCheck) {
        try {
            Objects.ensure(sizeToCheck == 128 || sizeToCheck == 192 || sizeToCheck == 256, "KeySize must be 128, 192 or 256 (bits)");
            int maxKeyLen = Cipher.getMaxAllowedKeyLength(CIPHER_TRANSFORM_AES);
            LOG.debug("The max allowed key length for {} is {}!", CIPHER_TRANSFORM_AES, maxKeyLen);
            return sizeToCheck <= maxKeyLen;
        } catch (IllegalStateException ise) {
            LOG.debug("Invalid key size '{}' ({})!", sizeToCheck, ise.getMessage());
            return false;
        } catch (Exception e) {
            LOG.debug("Cannot get max allowed key length for '{}': {}!", CIPHER_TRANSFORM_AES, e.getMessage());
            return false;
        }
    }

    /**
     * Generates a new pseudorandom salt of the specified length (bytes) using {@link SecureRandom} and SHA1PRNG.
     * <p>The length of the salt size should be same as block size <p/>
     * @param sizeInBytes salt size in bytes (a common value for AES is 16)
     * @return a random salt in the given size
     */
    public static byte[] generateSalt(int sizeInBytes) throws NoSuchAlgorithmException {
        byte[] salt = new byte[sizeInBytes];
        SecureRandom.getInstance(RND_NUM_ALGORITHM).nextBytes(salt);
        return salt;
    }

    /**
     * Generate a new pseudorandom initialisation vector in block size length (16 bytes / 128 bits) using {@link SecureRandom} and SHA1PRNG.
     * @return a Iv parameter spec object containing random generated 16 bytes
     */
    public static AlgorithmParameterSpec generateIV(CIPHERSPEC cipherSpecification) throws NoSuchAlgorithmException {
        byte[] iv = new byte[cipherSpecification.getIvBlockSize()];
        SecureRandom.getInstance(RND_NUM_ALGORITHM).nextBytes(iv);
        return cipherSpecification.getAlgoParamSpec(iv);
    }

    /**
     * Encrypts a stream of data with AES 128 bit.
     * The encrypted stream consists of
     * [16byte salt] + [16 byte IV] + [n byte cipherdata]
     * a header followed by the raw AES data. The header is broken down as follows:<br/>
     * <ul>
     * <li><b>keyLength</b>: AES key length in bytes (valid for 16, 24, 32) (1 byte)</li>
     * <li><b>salt</b>: pseudorandom salt used to derive keys from password (16 bytes)</li>
     * <li><b>authentication key</b> (derived from password and salt, used to check validity of password upon decryption) (8 bytes)</li>
     * <li><b>IV</b>: pseudorandom AES initialization vector (16 bytes)</li>
     * </ul>
     * @param password password to use for encryption
     * @param input an arbitrary byte stream to encryptAndMerge
     * @param output stream to which encrypted data will be written
     */
    public static void encryptStream(char[] password, InputStream input, OutputStream output) throws Exception {
        AESGC pbe = new AESGC(CIPHERSPEC.AES_CBC_PKCS5PADDING, KEY_SIZE_128_BITS, DEFAULT_SALT_SIZE, DEFAULT_ITERATIONS);
        byte[] salt = pbe.generateSalt();
        SecretKey key = pbe.generateKey(password, salt);
        output.write(salt);
        pbe.cipher.init(Cipher.ENCRYPT_MODE, key); //we want a new IV
        output.write(pbe.getInitialisationVector()); //write IV
        // read data from input into buffer, encryptAndMerge and write to output
        byte[] buffer = new byte[1024];
        int numRead;
        byte[] encrypted;
        while ((numRead = input.read(buffer)) > 0) {
            encrypted = pbe.cipher.update(buffer, 0, numRead);
            if (encrypted != null) {
                output.write(encrypted);
            }
        }
        byte[] data = pbe.cipher.doFinal();
        if (data != null) {
            output.write(data);
        }
    }

    /**
     * Decryption method for streams previously encrypted by {@link #encryptStream(char[], InputStream, OutputStream)}
     * @param password the same password used by the encryption
     * @param input the input data as stream object
     * @param output the output data as stream object
     * @throws Exception any
     */
    public static void decryptStream(char[] password, InputStream input, OutputStream output) throws Exception {
        byte[] salt = new byte[DEFAULT_SALT_SIZE];
        input.read(salt);
        AESGC pbe = new AESGC(CIPHERSPEC.AES_CBC_PKCS5PADDING, KEY_SIZE_128_BITS, DEFAULT_SALT_SIZE, DEFAULT_ITERATIONS);
        SecretKey key = pbe.generateKey(password, salt);
        byte[] iv = new byte[pbe.getCipherSpec().getIvBlockSize()]; // 16-byte I.V. regardless of key size
        input.read(iv);
        pbe.cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        // read data from input into buffer, decrypt and write to output
        byte[] buffer = new byte[1024];
        int numRead;
        byte[] decrypted;
        while ((numRead = input.read(buffer)) > 0) {
            decrypted = pbe.cipher.update(buffer, 0, numRead);
            if (decrypted != null) {
                output.write(decrypted);
            }
        }
        decrypted = pbe.cipher.doFinal();
        if (decrypted != null) {
            output.write(decrypted);
        }
    }

    /**
     * AES-Encrypts the given bytes and produces a url compatible base 64 string.<br/>
     * The encryption will be performed with a new salt and a new iv.
     * @return base64 string containing salt, iv and encrypted data.
     */
    public static String encrypt2Base64(char[] password, byte[] toEncrypt) throws Exception {
        AESGC pbe = new AESGC();
        byte[] salt = pbe.generateSalt();
        SecretKey cryptKey = pbe.generateKey(password, salt);
        byte[] encrypted = pbe.encryptAndMerge(cryptKey, salt, toEncrypt);
        return Crypto.Base64.encode2String(encrypted);
    }

    /**
     * Decrypts a base64 encoded string which was encrypted by {@link #encrypt2Base64(char[], byte[])}
     * @param ciphertext salt + iv + encoded data returned by {@link #encrypt2Base64(char[], byte[])}
     * @return plain text as utf-8 string
     */
    public static String decryptBase64(char[] password, String ciphertext) throws Exception {
        AESGC pbe = new AESGC();
        byte[] cipherBytes = Crypto.Base64.decode(ciphertext);
        byte[] decryptData = pbe.decryptMergedData(password, cipherBytes);
        return new String(decryptData, "UTF-8");
    }

    public static byte[] getIVBytes(AlgorithmParameterSpec iv) {
        if (iv instanceof IvParameterSpec) {
            return ((IvParameterSpec) iv).getIV();
        } else if (iv instanceof GCMParameterSpec) {
            return ((GCMParameterSpec) iv).getIV();
        } else {
            throw new UnsupportedOperationException("Unknown AlgorithmParameterSpec");
        }
    }

    public CIPHERSPEC getCipherSpec() {
        return cipherSpec;
    }

    public AlgorithmParameterSpec generateIV(byte[] iv) throws NoSuchAlgorithmException {
        return this.cipherSpec.getAlgoParamSpec(iv);
    }

    /** The AES key size. Valid values are 128, 192 or 256 bits. */
    public int getKeySize() {
        return keySize;
    }

    /** Salt size in Bytes. */
    public int getSaltSize() {
        return saltSize;
    }

    /** Initialisation vector size in Bytes. */
    public int getIVSize() {
        return AES_BLOCK_SIZE;
    }

    /**
     * Generates a new pseudorandom salt of the specified length (bytes) using {@link SecureRandom} and the 'SHA1PRNG' algorithm.
     * The salt length is specified by the custom constructor or 16 bytes by using the default constructor!
     * <p>The length of the salt size should be same as block size <p/>
     * @return a random salt usually 16 bytes (if not customized)
     */
    public byte[] generateSalt() throws NoSuchAlgorithmException {
        byte[] salt = new byte[getSaltSize()];
        SecureRandom.getInstance(RND_NUM_ALGORITHM).nextBytes(salt);
        return salt;
    }

    /**
     * Generates a AES key in the wanted size, using a given password and salt and the default amount of password iterations.
     * This method uses the either the default password iterations or the custom password iterations retrieved by {@link #getPwdIterations()}
     * @param password the password characters used for the key
     * @param salt the salt bytes used for the key
     * @return a java key object needed for AES encryption and decryption
     */
    public SecretKey generateKey(char[] password, byte[] salt) throws InvalidKeySpecException {
        return generateKey(password, salt, getPwdIterations());
    }

    /**
     * Generates a AES key in the wanted size, using a given password and salt and the specified amount of iterations.
     * <p>Watch out because this method can become a bottleneck! Tuning can be done e.g. by decreasing iterations</p>
     * @param password the password characters used for the key
     * @param salt the salt bytes used for the key
     * @param iterations the amount of iterations which will be applied to the key
     * @return a java key object needed for AES encryption and decryption
     */
    public SecretKey generateKey(char[] password, byte[] salt, int iterations) throws InvalidKeySpecException {
        Objects.notNull(password, "Parameter 'password' may not be null!");
        Objects.notNull(salt, "Parameter 'salt' may not be null!");
        Objects.ensure(salt.length == getSaltSize(), "AES object has been set to a salt size of {}! Your salt size ({}) does not match!", getSaltSize(), salt.length);
        //Generating 128/192/256-bit key using 16-byte salt doing n iterations
        KeySpec spec = new PBEKeySpec(password, salt, iterations, getKeySize());
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, CIPHER_TRANSFORM_AES);
    }

    /**
     * Retrieves the initialisation vector from the cipher object.
     * @return the iv depending of the specification (CBC/GC)
     */
    public byte[] getInitialisationVector() throws InvalidParameterSpecException {
        if (cipher.getIV() != null) {
            return cipher.getIV(); //this does only work if a encryption has been done!
        } else {
            if (CIPHERSPEC.AES_GCM_NOPADDING == cipherSpec) {
                AlgorithmParameters params = cipher.getParameters();
                return params.getParameterSpec(GCMParameterSpec.class).getIV();
            } else if (CIPHERSPEC.AES_CBC_PKCS5PADDING == cipherSpec) {
                AlgorithmParameters params = cipher.getParameters();
                return params.getParameterSpec(IvParameterSpec.class).getIV();
            } else {
                throw new UnsupportedOperationException("Cannot get IV for a unknown cipher spec: " + cipherSpec);
            }
        }
    }

    /**
     * Decrypts merged data which means cipher data must be Salt+IV+Data.
     * @param password must be the same password as used by the encryption
     * @param concatenatedData must be the encrypted data (Salt+IV+Data) usually created by {@link #encryptAndMerge(SecretKey, byte[], byte[])}
     * @return the plain data which can be used to create a new {@link String} object in case of text data
     * @throws Exception any
     */
    public byte[] decryptMergedData(char[] password, byte[] concatenatedData) throws Exception {
        byte[] salt = extractSalt(concatenatedData);
        //System.out.println("salt: "+ DatatypeConverter.printHexBinary(salt));
        byte[] iv = extractIV(concatenatedData);
        //System.out.println("iv: "+ DatatypeConverter.printHexBinary(iv));
        byte[] data = extractEncryptedData(concatenatedData);
        //System.out.println("data: "+ DatatypeConverter.printHexBinary(data));
        return decrypt(password, salt, iv, data);
    }

    /**
     * AES decryption where the key will be created using the following parameters. For performance reasons you
     * should create the key only once and pass it to {@link #decrypt(SecretKey, byte[], byte[])}
     * @param password the password used to generate the AES key
     * @param salt the salt bytes used to generate the AES key
     * @param iv the initialisation vector used to initialise the cipher object
     * @param cipherdata the data to be decrypted (can be text or any byte data)
     * @return the decrypted byte data (if it is a text you have to pass the bytes to a new {@link String} object
     * @throws Exception any
     */
    public byte[] decrypt(char[] password, byte[] salt, byte[] iv, byte[] cipherdata) throws Exception {
        SecretKey key = generateKey(password, salt);
        return decrypt(key, iv, cipherdata);
    }

    /**
     * AES decryption where a previously generated key can be passed in. For performance reasons the key should be created only once
     * @param key the secret key - eg. by using {@link #generateKey(char[], byte[])}
     * @param iv must be the same initialisation vector as used by the encryption - eg. created with {@link #generateIV(CIPHERSPEC)}
     * @param cipherdata the data to be decrypted (can be text or any byte data)
     * @return the decrypted byte data (if it is a text you have to pass the bytes to a new {@link String} object
     * @throws Exception any
     */
    public byte[] decrypt(SecretKey key, byte[] iv, byte[] cipherdata) throws Exception {
        if (cipherSpec == CIPHERSPEC.AES_GCM_NOPADDING) {
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * Byte.SIZE, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            cipher.updateAAD(AAD);
        } else if (cipherSpec == CIPHERSPEC.AES_CBC_PKCS5PADDING) {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        } else {
            throw new UnsupportedOperationException("Unknown Cipher Spec: " + cipherSpec);
        }
        //javax.crypto.AEADBadTagException: Tag mismatch!
        return cipher.doFinal(cipherdata);
    }

    /**
     * Encrypts data using the given key and salt and merges salt + iv + cipherdata.
     * Fastest way to encryptAndMerge mass data if the same key is used.
     * @param key the secret key - eg. created by {@link #generateKey(char[], byte[])}
     * @param salt the salt - eg. created by {@link #generateSalt()}
     * @param plain the data to be encrypted - can be text or anything else!
     * @return the encrypted data where salt + iv + encrypted data has been merged together
     * @throws Exception any
     */
    public byte[] encryptAndMerge(SecretKey key, byte[] salt, byte[] plain) throws Exception {
        AlgorithmParameterSpec iv = generateIV(this.cipherSpec);
        byte[] ivBytes;
        if (iv instanceof IvParameterSpec) {
            ivBytes = ((IvParameterSpec) iv).getIV();
        } else if (iv instanceof GCMParameterSpec) {
            ivBytes = ((GCMParameterSpec) iv).getIV();
        } else {
            throw new UnsupportedOperationException("Unknown AlgorithmParameterSpec");
        }
        return concat(salt, ivBytes, encrypt(key, iv, plain));
    }

    /**
     * Encrypts data using the given key and a custom initialisation vector.
     * Fastest way to encrypt mass data if the same key can be used.
     * @param key the secret key - eg. created by {@link #generateKey(char[], byte[])}
     * @param algoParamSpec the initialisation vector as a IvParameterSpec object - length must be 16 bytes!
     * for performance reasons there is no check for the correctness of the IV (eg. length)
     * @param plain the data to be encrypted - can be text or anything else!
     * @return the encrypted data (salt + iv + encrypted data)
     * @throws Exception any
     */
    public byte[] encrypt(SecretKey key, AlgorithmParameterSpec algoParamSpec, byte[] plain) throws Exception {
        try {
            if (CIPHERSPEC.AES_GCM_NOPADDING == cipherSpec) { //AES-GCM
                final int GCM_NONCE_LENGTH = 12; // iv (todo check length)
                final int GCM_TAG_LENGTH = 16; // in bytes
                final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, getIvBytes(algoParamSpec));
                cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
                /* AAD does not have to be used at all, the IV is already included in GCM mode encryption.  */
                cipher.updateAAD(AAD);
            } else if (CIPHERSPEC.AES_CBC_PKCS5PADDING == cipherSpec) { //AES-CBC
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(getIvBytes(algoParamSpec)));
            } else {
                throw new UnsupportedOperationException("Cannot encrypt with a unknown cipher spec: " + cipherSpec);
            }
        } catch (InvalidKeyException keyex) {
            if (key != null && key.getEncoded() != null) {
                throw new InvalidKeyException("Illegal key size of " + (key.getEncoded().length * Byte.SIZE) + " bit! JCE?");
            } else {
                throw keyex;
            }
        }
        return cipher.doFinal(plain);
    }

    /**
     * Encrypts data using the given key and salt and a custom initialisation vector and merges salt + iv + cipherdata.
     * Fastest way to encryptAndMerge mass data if the same key is used.
     * @param key the secret key - eg. created by {@link #generateKey(char[], byte[])}
     * @param salt the salt - eg. created by {@link #generateSalt()}
     * @param iv the initialisation vector as a IvParameterSpec object - length must be 16 bytes
     * @param plain the data to be encrypted - can be text or anything else!
     * @return the encrypted data (salt + iv + encrypted data)
     * @throws Exception any
     */
    public byte[] encryptAndMerge(SecretKey key, byte[] salt, AlgorithmParameterSpec iv, byte[] plain) throws Exception {
        return concat(salt, getIvBytes(iv), encrypt(key, iv, plain)); //merge salt + iv + data
    }

    public byte[] getIvBytes(AlgorithmParameterSpec iv) {
        if (this.cipherSpec == CIPHERSPEC.AES_CBC_PKCS5PADDING) {
            return ((IvParameterSpec) iv).getIV();
        } else if (this.cipherSpec == CIPHERSPEC.AES_GCM_NOPADDING) {
            return ((GCMParameterSpec) iv).getIV();
        } else {
            throw new UnsupportedOperationException("Unknown AlgorithmParameterSpec: " + this.cipherSpec);
        }
    }

    /**
     * Merges the salt and initialisation vector and the encrypted data
     * @param salt can be of any length
     * @param iv must be of length {@link #AES_BLOCK_SIZE}
     * @param encrypted any encrypted data
     * @return Salt + IV + Encrypted Data
     */
    private byte[] concat(byte[] salt, byte[] iv, byte[] encrypted) {
        byte[] concatenated = new byte[salt.length + iv.length + encrypted.length];
        int pos = 0;
        System.arraycopy(salt, 0, concatenated, pos, salt.length); //copy the salt in the new array
        pos += salt.length;
        System.arraycopy(iv, 0, concatenated, pos, iv.length); //copy the iv in the new array
        pos += iv.length;
        System.arraycopy(encrypted, 0, concatenated, pos, encrypted.length); //copy the ciphertext in the new array
        return concatenated;
    }

    /**
     * Extracts the salt from a merged byte array.
     * @param encrypted merged data - must be Salt(size will be retrieved by {@link #getSaltSize()} + IV + Data
     * @return the raw salt bytes
     */
    public byte[] extractSalt(byte[] encrypted) {
        byte[] salt = new byte[getSaltSize()];
        System.arraycopy(encrypted, 0, salt, 0, getSaltSize());
        return salt;
    }

    /**
     * Extract the initialization vector from a merged byte array.
     * @param encrypted merged data - must be Salt(size will be retrieved by {@link #getSaltSize()} + IV + Data
     * @return the raw initialisation vector bytes
     */
    public byte[] extractIV(byte[] encrypted) {
        byte[] iv = new byte[AES_BLOCK_SIZE];
        System.arraycopy(encrypted, getSaltSize(), iv, 0, AES_BLOCK_SIZE);
        return iv;
    }

    /**
     * Extracts the raw encrypted data from a merged byte array.
     * @param encrypted merged data - must be Salt(size will be retrieved by {@link #getSaltSize()} + IV + Data
     * @return the raw AES encrypted data
     */
    public byte[] extractEncryptedData(byte[] encrypted) {
        int length = encrypted.length - getSaltSize() - AES_BLOCK_SIZE;
        byte[] data = new byte[encrypted.length - getSaltSize() - AES_BLOCK_SIZE];
        System.arraycopy(encrypted, getSaltSize() + AES_BLOCK_SIZE, data, 0, length);
        return data;
    }

    /** Getter for the amount of password iterations used by {@link #generateKey(char[], byte[])} */
    public int getPwdIterations() {
        return pwdIterations;
    }

    /** Setter for the amount of password iterations used by {@link #generateKey(char[], byte[])} */
    public void setPwdIterations(int pwdIterations) {
        this.pwdIterations = pwdIterations;
    }

    /**
     * [AES specification]+[KeySize]+[Key derivation specification ]+[Iterations]+[@hashCode]
     * @return AES/CBC/PKCS5Padding/128Bit/PBKDF2WithHmacSHA512/65536@45820e51
     */
    @Override
    public String toString() {
        return cipherSpec.getSpec() + "/" + keySize + "Bit/" + KEYGEN_SPEC + "/" + pwdIterations + "@" + Integer.toHexString(hashCode());
    }

    public enum CIPHERSPEC {
        /** AES-CBC is used in the Cipher Block Chaining (CBC) mode with a 128 bit initialization vector (IV). */
        AES_CBC_PKCS5PADDING("AES/CBC/PKCS5Padding", 16),

        /**
         * AES-GCM [SP800-38D] is an authenticated encryption mechanism. It is equivalent to doing these two operations in one step - AES encryption followed by HMAC signing.
         * AES-GCM shall be used with a 96 bit Initialization Vector (IV) and a 128 bit Authentication Tag (T). The cipher text contains the IV first, followed by the encrypted octets and finally the Authentication tag. No padding should be used during encryption. During decryption the implementation should compare the authentication tag computed during decryption with the specified Authentication Tag, and fail if they don't match.
         * public static final int GCM_NONCE_LENGTH = 12; // in bytes
         * public static final int GCM_TAG_LENGTH = 16; // in bytes
         * <p>
         * The Galois/Counter Mode (GCM) is a generic authenticated encryption block cipher mode.
         * AES-GCM has four inputs: an AES key, an initialization vector (IV), a plaintext content, and optional additional authenticated data (AAD).
         * AES-GCM generates two outputs: a ciphertext and message authentication code (also called an authentication tag).
         * the AES-GCM IV is referred to as a nonce. AAD is authenticated but not encrypted.
         * AAD has nothing to do with making it "more secure". The aim of AAD is to attach information to the ciphertext that is not encrypted, but is bound to the ciphertext in the sense that it cannot be changed or separated. (Conceptually, the MAC is computed over the AAD and the ciphertext together.)
         */
        AES_GCM_NOPADDING("AES/GCM/NoPadding", 12);
        private final String spec;
        private final int ivBlockSize;

        CIPHERSPEC(String spec, int ivBlockSize) {
            this.spec = spec;
            this.ivBlockSize = ivBlockSize;
        }

        public String getSpec() {
            return spec;
        }

        public int getIvBlockSize() {
            return ivBlockSize;
        }

        public AlgorithmParameterSpec getAlgoParamSpec(byte[] iV) {
            AlgorithmParameterSpec iv = null;
            if (AES_CBC_PKCS5PADDING == this) {
                iv = new IvParameterSpec(iV);
            } else if (AES_GCM_NOPADDING == this) {
                iv = new GCMParameterSpec(16 * Byte.SIZE, iV);
            }
            return iv;
        }
    }

    /** Default values which can be used to change AES encryption. */
    public static class Defaults {
        /** Amount of iterations used for key generation. */
        public static final int DEFAULT_ITERATIONS = 65536;

        /** Length of the Salt to be used in bytes. 16 bytes = 128 bit */
        public static final int DEFAULT_SALT_SIZE_CBC = 16;

        /** Length of the Salt to be used in bytes. 12 bytes = 96 bit */
        public static final int DEFAULT_SALT_SIZE_GC = 12;

        /** Constant value for a 16 byte - 128 bit AES key. */
        public static final int KEY_SIZE_128_BITS = 128;
        /** Constant value for a 24 byte - 192 bit AES key. */
        public static final int KEY_SIZE_192_BITS = 192;
        /** Constant value for a 32 byte - 256 bit AES key. */
        public static final int KEY_SIZE_256_BITS = 256;
    }
}
