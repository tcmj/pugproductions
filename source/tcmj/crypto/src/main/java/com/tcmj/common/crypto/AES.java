package com.tcmj.common.crypto;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
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
 * Have a look on the JUnit test for detailed examples to use this class.
 * @author tcmj - Thomas Deutsch
 * @since 2.15.8
 */
public class AES {

    /** slf4j Logging Framework. */
    private static final Logger LOG = LoggerFactory.getLogger(AES.class);
    /** AES specification: Cipher Block Chaining Mode (CBC), Padding needed because of fixed block length */
    private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";
    /** Key derivation specification - changing will break existing streams! */
    private static final String KEYGEN_SPEC = "PBKDF2WithHmacSHA512";
    /** Random number algorithm used by the generate Salt and IV methods. */
    private static final String RND_NUM_ALGORITHM = "SHA1PRNG";
    /** Length of the Initialization Vector in bytes. 16 bytes = 128 bit. FIXED for AES! */
    private static final int FIXED_AES_BLOCK_SIZE = 16;
    /** Cipher transformation : AES */
    private static String CIPHER_TRANSFORM_AES = "AES";
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
     * Default constructor for AES with {@link Defaults#KEY_SIZE_128_BITS} bit key size
     * using {@link Defaults#DEFAULT_ITERATIONS} password iterations and a default salt
     * size of {@link Defaults#DEFAULT_SALT_SIZE}
     */
    public AES() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this(KEY_SIZE_128_BITS, DEFAULT_SALT_SIZE, DEFAULT_ITERATIONS);
    }


    /**
     * Constructor for AES where you can define custom values.
     * @param keySize must be one of {@link Defaults#KEY_SIZE_128_BITS}, {@link Defaults#KEY_SIZE_192_BITS} or {@link Defaults#KEY_SIZE_256_BITS}
     * @param saltSize a common salt size is 16 (bytes)
     * @param passIterations the password iterations used by the AES algorithm. A high value decreases performance.
     */
    public AES(final int keySize, final int saltSize, final int passIterations) throws NoSuchAlgorithmException, NoSuchPaddingException {
        Objects.ensure(keySize == 128 || keySize == 192 || keySize == 256, "AES key size must be 128, 192 or 256 (bits)");
        this.keySize = keySize;
        this.saltSize = Objects.nonZero(saltSize, "Salt size must be > 0 (bytes)!");
        this.pwdIterations = Objects.nonZero(passIterations, "Password iterations must be > 0!");
        factory = SecretKeyFactory.getInstance(KEYGEN_SPEC);
        cipher = Cipher.getInstance(CIPHER_SPEC);
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
    public static IvParameterSpec generateIV() throws NoSuchAlgorithmException {
        byte[] iv = new byte[FIXED_AES_BLOCK_SIZE];
        SecureRandom.getInstance(RND_NUM_ALGORITHM).nextBytes(iv);
        return new IvParameterSpec(iv);
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
        AES pbe = new AES(KEY_SIZE_128_BITS, DEFAULT_SALT_SIZE, DEFAULT_ITERATIONS);
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
        AES pbe = new AES(KEY_SIZE_128_BITS, DEFAULT_SALT_SIZE, DEFAULT_ITERATIONS);
        SecretKey key = pbe.generateKey(password, salt);
        byte[] iv = new byte[FIXED_AES_BLOCK_SIZE]; // 16-byte I.V. regardless of key size
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
        AES pbe = new AES();
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
        AES pbe = new AES();
        byte[] cipherBytes = Crypto.Base64.decode(ciphertext);
        byte[] decryptData = pbe.decryptMergedData(password, cipherBytes);
        return new String(decryptData, "UTF-8");
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
        return FIXED_AES_BLOCK_SIZE;
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
     * @return params.getParameterSpec(IvParameterSpec.class).getIV();
     */
    public byte[] getInitialisationVector() throws InvalidParameterSpecException {
        if (cipher.getIV() != null) {
            return cipher.getIV(); //this does only work if a encryption has been done!
        } else {
            AlgorithmParameters params = cipher.getParameters();
            return params.getParameterSpec(IvParameterSpec.class).getIV();
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
        byte[] iv = extractIV(concatenatedData);
        byte[] data = extractEncryptedData(concatenatedData);
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
     * @param iv must be the same initialisation vector as used by the encryption - eg. created with {@link #generateIV()}
     * @param cipherdata the data to be decrypted (can be text or any byte data)
     * @return the decrypted byte data (if it is a text you have to pass the bytes to a new {@link String} object
     * @throws Exception any
     */
    public byte[] decrypt(SecretKey key, byte[] iv, byte[] cipherdata) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
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
//        cipher.init(Cipher.ENCRYPT_MODE, key);
//        byte[] iv = getInitialisationVector();
//        byte[] encrypted = cipher.doFinal(plain);
//        return concat(salt, iv, encrypted);

        IvParameterSpec iv = generateIV();
        return concat(salt, iv.getIV(), encrypt(key, iv, plain));
    }

    /**
     * Encrypts data using the given key and a custom initialisation vector.
     * Fastest way to encrypt mass data if the same key can be used.
     * @param key the secret key - eg. created by {@link #generateKey(char[], byte[])}
     * @param iv the initialisation vector as a IvParameterSpec object - length must be 16 bytes!
     * for performance reasons there is no check for the correctness of the IV (eg. length)
     * @param plain the data to be encrypted - can be text or anything else!
     * @return the encrypted data (salt + iv + encrypted data)
     * @throws Exception any
     */
    public byte[] encrypt(SecretKey key, IvParameterSpec iv, byte[] plain) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
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
    public byte[] encryptAndMerge(SecretKey key, byte[] salt, IvParameterSpec iv, byte[] plain) throws Exception {
        return concat(salt, iv.getIV(), encrypt(key, iv, plain)); //merge salt + iv + data
    }

    /**
     * Merges the salt and initialisation vector and the encrypted data
     * @param salt can be of any length
     * @param iv must be of length {@link #FIXED_AES_BLOCK_SIZE}
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
        byte[] iv = new byte[FIXED_AES_BLOCK_SIZE];
        System.arraycopy(encrypted, getSaltSize(), iv, 0, FIXED_AES_BLOCK_SIZE);
        return iv;
    }

    /**
     * Extracts the raw encrypted data from a merged byte array.
     * @param encrypted merged data - must be Salt(size will be retrieved by {@link #getSaltSize()} + IV + Data
     * @return the raw AES encrypted data
     */
    public byte[] extractEncryptedData(byte[] encrypted) {
        int length = encrypted.length - getSaltSize() - FIXED_AES_BLOCK_SIZE;
        byte[] data = new byte[encrypted.length - getSaltSize() - FIXED_AES_BLOCK_SIZE];
        System.arraycopy(encrypted, getSaltSize() + FIXED_AES_BLOCK_SIZE, data, 0, length);
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
        return CIPHER_SPEC + "/" + keySize + "Bit/" + KEYGEN_SPEC + "/" + pwdIterations + "@" + Integer.toHexString(hashCode());
    }

    /** Default values which can be used to change AES encryption. */
    public static class Defaults {
        /** Amount of iterations used for key generation. */
        public static final int DEFAULT_ITERATIONS = 65536;
        /** Length of the Salt to be used in bytes. 16 bytes = 128 bit */
        public static final int DEFAULT_SALT_SIZE = 16;
        /** Constant value for a 16 byte - 128 bit AES key. */
        public static final int KEY_SIZE_128_BITS = 128;
        /** Constant value for a 24 byte - 192 bit AES key. */
        public static final int KEY_SIZE_192_BITS = 192;
        /** Constant value for a 32 byte - 256 bit AES key. */
        public static final int KEY_SIZE_256_BITS = 256;
    }
}
