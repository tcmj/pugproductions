package com.tcmj.common.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import static com.tcmj.common.crypto.AES.Defaults.DEFAULT_ITERATIONS;
import static com.tcmj.common.crypto.AES.Defaults.DEFAULT_SALT_SIZE;
import static com.tcmj.common.crypto.AES.Defaults.KEY_SIZE_128_BITS;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

/**
 * Tests of class {@link AES }
 * <p>There's a extended debugging mode which can be activated using jvm parameter: 'java.security.debug'</p>
 */
public class AESGCTest {

    @BeforeClass
    public static void initAAD() {
        AESGC.setAAD("Thomas und Claudia und Mirijam und Jonas".getBytes());
    }

    private AESGC createAESCBC() throws NoSuchAlgorithmException, NoSuchPaddingException {
        AESGC cbc = new AESGC(AESGC.CIPHERSPEC.AES_CBC_PKCS5PADDING, KEY_SIZE_128_BITS, DEFAULT_SALT_SIZE, DEFAULT_ITERATIONS);
        return cbc;
    }

    private AESGC createAESGC() throws NoSuchAlgorithmException, NoSuchPaddingException {
        AESGC gc = new AESGC(AESGC.CIPHERSPEC.AES_GCM_NOPADDING, KEY_SIZE_128_BITS, DEFAULT_SALT_SIZE, DEFAULT_ITERATIONS);
        return gc;
    }


    @Test
    public void testDefaults() throws Exception {
        assertThat("Coverage", new AESGC.Defaults(), notNullValue());
        assertThat("Default iterations", AESGC.Defaults.DEFAULT_ITERATIONS, is(65536));
        assertThat("Default 128 bit salt size", AESGC.Defaults.DEFAULT_SALT_SIZE_CBC, is(16));
        assertThat("Default 128 bit salt size", AESGC.Defaults.DEFAULT_SALT_SIZE_GC, is(12));
        assertThat("Default 128 bit AES key", AESGC.Defaults.KEY_SIZE_128_BITS, is(128));
        assertThat("Default 192 bit AES key", AESGC.Defaults.KEY_SIZE_192_BITS, is(192));
        assertThat("Default 256 bit AES key", AESGC.Defaults.KEY_SIZE_256_BITS, is(256));
    }

    @Test
    public void testConstructorValid() throws Exception {
        assertThat("128 bit", new AESGC(128, 1, 1), notNullValue());
        assertThat("192 bit", new AESGC(192, 1, 1), notNullValue());
        assertThat("256 bit", new AESGC(256, 1, 1), notNullValue());
    }

    @Test(expected = RuntimeException.class)
    public void testConstructorInvalidBitSize() throws Exception {
        new AESGC(100, 16, 1000);
    }

    @Test(expected = RuntimeException.class)
    public void testConstructorInvalidSaltSize() throws Exception {
        new AESGC(128, 0, 100);
    }

    @Test(expected = RuntimeException.class)
    public void testConstructorInvalidIterationCount() throws Exception {
        new AESGC(128, 16, 0);
    }

    @Test
    public void testToString() throws Exception {
        Assert.assertTrue("CBC", StringUtils.startsWith(createAESCBC().toString(), "AES/CBC/PKCS5Padding/128Bit/PBKDF2WithHmacSHA512/"));
        Assert.assertTrue("CBC-KEYSIZE", StringUtils.startsWith(new AESGC(AESGC.Defaults.KEY_SIZE_256_BITS, 8, 999).toString(), "AES/CBC/PKCS5Padding/256Bit/PBKDF2WithHmacSHA512/"));
        Assert.assertTrue("GC", StringUtils.startsWith(createAESGC().toString(), "AES/GCM/NoPadding/128Bit/PBKDF2WithHmacSHA512/"));
        Assert.assertTrue("GC-KEYSIZE", StringUtils.startsWith(new AESGC(AESGC.CIPHERSPEC.AES_GCM_NOPADDING, AESGC.Defaults.KEY_SIZE_256_BITS, 8, 999).toString(), "AES/GCM/NoPadding/256Bit/PBKDF2WithHmacSHA512/"));
    }

    @Test
    public void testGetKeySize() throws Exception {
        assertThat("default key size 128 bit", createAESCBC().getKeySize(), is(AESGC.Defaults.KEY_SIZE_128_BITS));
        assertThat("key size 192 bit", new AESGC(AESGC.Defaults.KEY_SIZE_192_BITS, 8, 10).getKeySize(), is(AESGC.Defaults.KEY_SIZE_192_BITS));
        assertThat("key size 256 bit", new AESGC(AESGC.Defaults.KEY_SIZE_256_BITS, 8, 10).getKeySize(), is(AESGC.Defaults.KEY_SIZE_256_BITS));
    }

    @Test
    public void testGetSaltSize() throws Exception {
        assertThat("default salt size 16 byte", new AESGC().getSaltSize(), is(AESGC.Defaults.DEFAULT_SALT_SIZE_CBC));
        assertThat("salt size 8 byte", new AESGC(128, 8, 10).getSaltSize(), is(8));
        assertThat("salt size 55 byte", new AESGC(128, 55, 10).getSaltSize(), is(55));
    }

    @Test
    public void testGetIVSize() throws Exception {

        AESGC cbc = new AESGC(AESGC.CIPHERSPEC.AES_CBC_PKCS5PADDING, KEY_SIZE_128_BITS, DEFAULT_SALT_SIZE, DEFAULT_ITERATIONS);
        assertThat("AES CBC size 16 byte", cbc.getIVSize(), is(16));

        AESGC gc = new AESGC(AESGC.CIPHERSPEC.AES_GCM_NOPADDING, KEY_SIZE_128_BITS, DEFAULT_SALT_SIZE, DEFAULT_ITERATIONS);
        assertThat("AES GC size 12 byte", gc.getIVSize(), is(12));

        assertThat("iv size using custom constructor", new AESGC(256, 8, 10).getIVSize(), is(16));
    }

    @Test
    public void testIsKeySizeAllowed() throws Exception {
        //Standard Java installation (Standard JCE)
        assertThat("Check AES key size 128", AESGC.isKeySizeAllowed(AESGC.Defaults.KEY_SIZE_128_BITS), is(true)); //this is the only allowed one by default
        assertThat("Check AES key size 192", AESGC.isKeySizeAllowed(AESGC.Defaults.KEY_SIZE_192_BITS), is(false)); //valid but locked
        assertThat("Check AES key size 256", AESGC.isKeySizeAllowed(AESGC.Defaults.KEY_SIZE_256_BITS), is(false)); //valid but locked
        //Hack to emulate Extended Java installation (JCE jurisdiction policy files)
        Crypto.removeCryptographyRestrictions();
        //..now we can also use 192 and 256 bit key size for AES
        assertThat("Check AES key size 128", AESGC.isKeySizeAllowed(128), is(true));
        assertThat("Check AES key size 192", AESGC.isKeySizeAllowed(192), is(true));
        assertThat("Check AES key size 256", AESGC.isKeySizeAllowed(256), is(true));

        //Error case ... throwing no exception
        assertThat("Check invalid AES key size 333", AESGC.isKeySizeAllowed(333), is(false));

    }

    @Test
    public void testGenerateSalt() throws Exception {
        assertThat("default 16 byte salt", new AESGC().generateSalt().length, is(16));
        assertThat("16 byte salt", new AESGC(128, 20, 100).generateSalt().length, is(20));
        assertThat("should create different salts", DatatypeConverter.printHexBinary(new AESGC().generateSalt()), not(equalTo(DatatypeConverter.printHexBinary(new AESGC().generateSalt()))));
    }

    @Test
    public void testGenerateSaltWithSize() throws Exception {
        assertThat("8 byte salt", AESGC.generateSalt(8).length, is(8));
        assertThat("16 byte salt", AESGC.generateSalt(16).length, is(16));
        assertThat("should create different salts", DatatypeConverter.printHexBinary(AESGC.generateSalt(16)), not(equalTo(DatatypeConverter.printHexBinary(AESGC.generateSalt(16)))));
    }

    @Test
    public void testGenerateIV() throws Exception {
        AlgorithmParameterSpec ivParameterSpec = AESGC.generateIV(AESGC.CIPHERSPEC.AES_GCM_NOPADDING);
        assertThat("generateIV() should return non null IvParameterSpec obj", ivParameterSpec, notNullValue());
        //TODO assertThat("generateIV() should contain non null byte array", ivParameterSpec.getIV(), notNullValue());
        //TODO assertThat("generateIV() 16 bytes length", ivParameterSpec.getIV().length, is(16));
        //TODOassertThat("should create different ivs", DatatypeConverter.printHexBinary(AESGC.generateIV().getIV()), not(equalTo(DatatypeConverter.printHexBinary(AESGC.generateIV().getIV()))));
    }

    @Test
    public void testGenerateKey() throws Exception {
        AESGC aes = new AESGC(); //128bit
        char[] password = "Kindergarten".toCharArray();
        byte[] salt = aes.generateSalt();
        SecretKey key = aes.generateKey(password, salt);
        assertThat("generateKey(char[],byte[]) should not return null", key, notNullValue());
        assertThat("generateKey(char[],byte[]) should return AES key", key.getAlgorithm(), equalTo("AES"));
        assertThat("generateKey(char[],byte[]) should not be destroyed", key.isDestroyed(), is(false));
        assertThat("should create same ", DatatypeConverter.printHexBinary(aes.generateKey(password, salt).getEncoded()), equalTo(DatatypeConverter.printHexBinary(aes.generateKey(password, salt).getEncoded())));
    }

    @Test
    public void testGenerateKeyWithCustomIterationAmount() throws Exception {
        AESGC aes = new AESGC(); //128bit
        char[] password = "Kindergarten".toCharArray();
        byte[] salt = aes.generateSalt();
        int iterations = 8864; //performance!
        SecretKey key = aes.generateKey(password, salt, iterations);
        assertThat("generateKey(char[],byte[],int) should not return null", key, notNullValue());
        assertThat("generateKey(char[],byte[],int) should return AES key", key.getAlgorithm(), equalTo("AES"));
        assertThat("generateKey(char[],byte[],int) should not be destroyed", key.isDestroyed(), is(false));
        SecretKey key2 = new AESGC().generateKey(password, salt, iterations);
        assertThat("should create same ", DatatypeConverter.printHexBinary(key.getEncoded()), equalTo(DatatypeConverter.printHexBinary(key2.getEncoded())));
    }

    @Test
    public void testGetInitialisationVector() throws Exception {
        AESGC cbc = createAESCBC(), gc = createAESGC();
        assertThat("gc getInitialisationVector should never return null", gc.getInitialisationVector(), notNullValue());
        assertThat("cbc getInitialisationVector should never return null", cbc.getInitialisationVector(), notNullValue());

        //if no encryption has been made, the method should return always new random values!
        byte[] iV = cbc.getInitialisationVector();
        byte[] iV2 = cbc.getInitialisationVector();
        assertThat("cbc should have a iv length of 16", iV.length, is(16));
        assertThat("cbc should create different ivs 1 not 2", DatatypeConverter.printHexBinary(iV), not(equalTo(DatatypeConverter.printHexBinary(iV2))));
        assertThat("cbc should create different ivs 2", DatatypeConverter.printHexBinary(createAESCBC().getInitialisationVector()), not(equalTo(DatatypeConverter.printHexBinary(createAESCBC().getInitialisationVector()))));

        iV = gc.getInitialisationVector();
        iV2 = gc.getInitialisationVector();
        assertThat("gc should have a iv length of 12", iV.length, is(12));
        assertThat("gc should create different ivs 1 not 2", DatatypeConverter.printHexBinary(iV), not(equalTo(DatatypeConverter.printHexBinary(iV2))));
        assertThat("gc should create different ivs 2", DatatypeConverter.printHexBinary(createAESGC().getInitialisationVector()), not(equalTo(DatatypeConverter.printHexBinary(createAESGC().getInitialisationVector()))));
    }

    @Test
    public void testGetInitialisationVectorSameCBC() throws Exception {
        /* for the same encryption the same IV should be returned by getInitialisationVector() ! ! ! */

        AESGC aes = new AESGC(AESGC.CIPHERSPEC.AES_CBC_PKCS5PADDING, 128, 48, 1);
        byte[] salt = aes.generateSalt();
        aes.encryptAndMerge(aes.generateKey("mooh".toCharArray(), salt), salt, "--xx--xx--xx--".getBytes());
        byte[] iV1 = aes.getInitialisationVector();
        byte[] iV2 = aes.getInitialisationVector();
        assertThat("IV 1 is same as IV 2", DatatypeConverter.printHexBinary(iV1), equalTo(DatatypeConverter.printHexBinary(iV2)));

        byte[] salt2 = aes.generateSalt();
        aes.encryptAndMerge(aes.generateKey("mooh".toCharArray(), salt2), salt2, "--xx--xx--xx--".getBytes());
        byte[] iV3 = aes.getInitialisationVector();
        byte[] iV4 = aes.getInitialisationVector();
        assertThat("IV 3 is same as IV 4", DatatypeConverter.printHexBinary(iV3), equalTo(DatatypeConverter.printHexBinary(iV4)));
        assertThat("IV 1 is NOT same as IV 3", DatatypeConverter.printHexBinary(iV1), not(equalTo(DatatypeConverter.printHexBinary(iV3))));
        assertThat("IV 2 is NOT same as IV 4", DatatypeConverter.printHexBinary(iV2), not(equalTo(DatatypeConverter.printHexBinary(iV4))));
    }

    @Test
    public void testGetInitialisationVectorSameGC() throws Exception {
        /* for the same encryption the same IV should be returned by getInitialisationVector() ! ! ! */
        AESGC aes = new AESGC(AESGC.CIPHERSPEC.AES_GCM_NOPADDING, 128, 96, 1234);
        byte[] salt = aes.generateSalt();
        aes.encryptAndMerge(aes.generateKey("mooh".toCharArray(), salt), salt, "--xx--xx--xx--".getBytes());
        byte[] iV1 = aes.getInitialisationVector();
        byte[] iV2 = aes.getInitialisationVector();
        assertThat("IV 1 is same as IV 2", DatatypeConverter.printHexBinary(iV1), equalTo(DatatypeConverter.printHexBinary(iV2)));

        byte[] salt2 = aes.generateSalt();
        aes.encryptAndMerge(aes.generateKey("mooh".toCharArray(), salt2), salt2, "--xx--xx--xx--".getBytes());
        byte[] iV3 = aes.getInitialisationVector();
        byte[] iV4 = aes.getInitialisationVector();
        assertThat("IV 3 is same as IV 4", DatatypeConverter.printHexBinary(iV3), equalTo(DatatypeConverter.printHexBinary(iV4)));
        assertThat("IV 1 is NOT same as IV 3", DatatypeConverter.printHexBinary(iV1), not(equalTo(DatatypeConverter.printHexBinary(iV3))));
        assertThat("IV 2 is NOT same as IV 4", DatatypeConverter.printHexBinary(iV2), not(equalTo(DatatypeConverter.printHexBinary(iV4))));
    }

    @Test
    public void testDecryptMergedDataCBC() throws Exception {
        char[] password = "dg43zfh$FDD!".toCharArray();
        String text = "we want this to be encrypted!";
        byte[] encrypted = DatatypeConverter.parseHexBinary("FD3A39C36685DDF6FC997F7124732689D579D1CEAD5432548DCCB6399D1AAF1B1B49E9652B3C3844DD016FDDD10CCE43F2EA70EEAA669D705F9387BE9AB49C7A");
        assertThat("Decrypting: " + text, new String(createAESCBC().decryptMergedData(password, encrypted)), equalTo(text));
    }

    @Test
    public void testDecryptMergedDataGC() throws Exception {
        char[] password = "t.c.m.j".toCharArray();
        String text = "Encrypt";
        byte[] encrypted = DatatypeConverter.parseHexBinary("6C87628C44B009B69190651142F8E075B30B7F05409E0F1308DDCAB2B4D926AD892CD8F54FC81807702749497EC6D93B933216");
        assertThat("Decrypting: " + text, new String(createAESGC().decryptMergedData(password, encrypted)), equalTo(text));
    }

    @Test
    public void testDecryptWithKeyCBC() throws Exception {
        /* decrypt method which takes a key as argument. */
        AESGC decryptor = createAESCBC();
        byte[] mySalt = DatatypeConverter.parseHexBinary("6C87628C44B009B69190651142F8E075");
        SecretKey myKey = decryptor.generateKey("verySecretPassword".toCharArray(), mySalt);
        byte[] iV = DatatypeConverter.parseHexBinary("2F2E72ACA494E8B045D25F2DC317D6FA");
        byte[] cipherData = DatatypeConverter.parseHexBinary("F9D5D173F90AC3DE0F976E3CAE0E9DBFE906F6D1BC5FBC1022582FEC1AD65E24276003EB20E69E77DB36BD40A8AB52A04A62B7EE7554EA5529611ADCF6E20E4A");
        byte[] decrypt = decryptor.decrypt(myKey, iV, cipherData);
        String result = new String(decrypt);
        assertThat("AESGC.decrypt(Key, IV, CipherData)", result, equalTo("if you can read this you have successfully decrypted my brain!"));
    }

    @Test
    public void testDecryptWithKeyGC() throws Exception {
        /* decrypt method which takes a key as argument. */
        AESGC decryptor = createAESGC();
        byte[] mySalt = DatatypeConverter.parseHexBinary("0A66CF031E9EA8160F965F4E499E3AC8");
        SecretKey myKey = decryptor.generateKey("verySecretPassword".toCharArray(), mySalt);
        byte[] iV = DatatypeConverter.parseHexBinary("0D2856AD07063E06BE8F317C");
        byte[] cipherData = DatatypeConverter.parseHexBinary("673B6EBDF4713CFFEC4D625A85A54A1A7E15A03D569234EBA80E26D36AC9196E929EA81CFA5DE67D6051B0769247B24FB9116D8C01B5A129971CB2A4C4E371B729D9B0D0A1640BD435B7E0A9D7A6");
        byte[] decrypt = decryptor.decrypt(myKey, iV, cipherData);
        String result = new String(decrypt);
        assertThat("AESGC.decrypt(Key, IV, CipherData)", result, equalTo("if you can read this you have successfully decrypted my brain!"));
    }

    @Test
    public void testDecryptCBC() throws Exception {
        /* decrypt method which builds the key internally and takes all arguments needed to do that. */
        AESGC decryptor = new AESGC(AESGC.CIPHERSPEC.AES_CBC_PKCS5PADDING, 128, 48, 500);
        byte[] mySalt = DatatypeConverter.parseHexBinary("4561EB6209C7EE43BAC6204DD0ABAF929A8D7A07FE04537D266DA20A8E3A8C434A25819348A88B0898150EB686E0DF2A");
        byte[] iV = DatatypeConverter.parseHexBinary("B30B7F05409E0F1308DDCAB27F75C9B6");
        byte[] cipherData = DatatypeConverter.parseHexBinary("8E44FC9B118FAAAEDDABD4BAC22FA5D1F17DCF8FAD4EDEC6047C0D8795E664BE");
        byte[] decrypt = decryptor.decrypt("t.c.m.j".toCharArray(), mySalt, iV, cipherData);
        assertThat("AESGC.decrypt(Key, IV, CipherData)", new String(decrypt), equalTo("TopSecretThisTimeWith!$%&/()"));
    }

    @Test
    public void testDecryptGC() throws Exception {
        /* decrypt method which builds the key internally and takes all arguments needed to do that. */
        AESGC decryptor = new AESGC(AESGC.CIPHERSPEC.AES_GCM_NOPADDING, 128, 48, 500);
        byte[] mySalt = DatatypeConverter.parseHexBinary("8943FE4121983BC8F683CB9ECEE53A87727AB97A91BBE1638966C758D1466E9C751DEACFD78D9B3319168DA91392F05A");
        byte[] iV = DatatypeConverter.parseHexBinary("B0EB32C69CC19B3E8CC71518");
        byte[] cipherData = DatatypeConverter.parseHexBinary("B336E260BCCA9CEDFA217A61FC71701C4AEFFBD439919E7CE0D969250F98759D42CF5E590721FF51306B43C1");
        byte[] decrypt = decryptor.decrypt("t.c.m.j".toCharArray(), mySalt, iV, cipherData);
        assertThat("AESGC.decrypt(Key, IV, CipherData)", new String(decrypt), equalTo("TopSecretThisTimeWith!$%&/()"));
    }

    @Test
    public void testEncryptWithoutMergeCBC() throws Exception {
        /* Pure AES Encryption without the final merge (key+salt+iv+data)... output is only the encrypted 'data' */
        AESGC aes = createAESCBC();
        byte[] salt = DatatypeConverter.parseHexBinary("6C87628C44B009B69190651142F8E075");
        byte[] iV = DatatypeConverter.parseHexBinary("B30B7F05409E0F1308DDCAB27F75C9B6");
        SecretKey key = aes.generateKey("t.c.m.j".toCharArray(), salt);
        AlgorithmParameterSpec iv = aes.generateIV(iV);

        byte[] encrypted = aes.encrypt(key, iv, "Encrypt".getBytes());
        assertThat("AESGC.encrypt(Key, IV, CipherData)", DatatypeConverter.printHexBinary(encrypted), equalTo("BF58EC6D318837E47FB764DD5E6291E8"));
    }

    @Test
    public void testEncryptWithoutMergeGC() throws Exception {
        /* Pure AES Encryption without the final merge (key+salt+iv+data)... output is only the encrypted 'data' */
        AESGC aes = createAESGC();
        byte[] salt = DatatypeConverter.parseHexBinary("6C87628C44B009B69190651142F8E075");
        byte[] iV = DatatypeConverter.parseHexBinary("B30B7F05409E0F1308DDCAB27F75C9B6");
        SecretKey key = aes.generateKey("t.c.m.j".toCharArray(), salt);
        AlgorithmParameterSpec iv = aes.generateIV(iV);
        byte[] encrypted = aes.encrypt(key, iv, "Encrypt".getBytes());
        assertThat("AESGC.encrypt(Key, IV, CipherData)", DatatypeConverter.printHexBinary(encrypted), equalTo("EF47FBF385952A25B97D68AF9992CBA8DBE1667756A110"));
    }

    @Test
    public void testEncryptAndMergeCBC() throws Exception {
        /* same input parameters produce always same output parameters!*/
        AESGC aes = createAESCBC();
        byte[] salt = DatatypeConverter.parseHexBinary("6C87628C44B009B69190651142F8E075");
        byte[] iV = DatatypeConverter.parseHexBinary("B30B7F05409E0F1308DDCAB27F75C9B6");
        SecretKey key = aes.generateKey("t.c.m.j".toCharArray(), salt);
        AlgorithmParameterSpec iv = aes.generateIV(iV);

        byte[] encrypted = aes.encryptAndMerge(key, salt, iv, "Encrypt".getBytes());
        assertThat("AESGC.encryptAndMerge", DatatypeConverter.printHexBinary(encrypted), equalTo("6C87628C44B009B69190651142F8E075B30B7F05409E0F1308DDCAB27F75C9B6BF58EC6D318837E47FB764DD5E6291E8"));
    }

    @Test
    public void testEncryptAndMergeGC() throws Exception {
        /* same input parameters produce always same output parameters!*/
        AESGC aes = createAESGC();
        byte[] salt = DatatypeConverter.parseHexBinary("6C87628C44B009B69190651142F8E075");
        byte[] iV = DatatypeConverter.parseHexBinary("B30B7F05409E0F1308DDCAB2");

////salt: 6C87628C44B009B69190651142F8E075
//        iv: B30B7F05409E0F1308DDCAB2
//        data: B4D926AD892CD8F54FC81807702749497EC6D93B933216
        SecretKey key = aes.generateKey("t.c.m.j".toCharArray(), salt);
        AlgorithmParameterSpec iv = aes.generateIV(iV);

        byte[] encrypted = aes.encryptAndMerge(key, salt, iv, "Encrypt".getBytes());

        String humanReadable = DatatypeConverter.printHexBinary(encrypted);
        System.out.println(": " + humanReadable);

        assertThat("AESGC.encryptAndMerge", DatatypeConverter.printHexBinary(encrypted), equalTo("6C87628C44B009B69190651142F8E075B30B7F05409E0F1308DDCAB2B4D926AD892CD8F54FC81807702749497EC6D93B933216"));
    }

    @Test
    public void testEncryptAndMergeWithoutIv() throws Exception {
         /* we encrypt (..and merge) with a random IV!*/
        AESGC aes = new AESGC();
        byte[] salt = DatatypeConverter.parseHexBinary("6C87628C44B009B69190651142F8E075");

        SecretKey key = aes.generateKey("t.c.m.j".toCharArray(), salt);
        byte[] encrypted = aes.encryptAndMerge(key, salt, "Encrypt".getBytes());
        String encryptedHex1 = DatatypeConverter.printHexBinary(encrypted);
        //we cannot define the expected result because of the random IV used!
        assertThat("AESGC.encryptAndMerge 1", encryptedHex1, not(equalTo("6C87628C44B009B69190651142F8E075B30B7F05409E0F1308DDCAB27F75C9B6BF58EC6D318837E47FB764DD5E6291E8")));

        byte[] encrypted2 = aes.encryptAndMerge(key, salt, "Encrypt".getBytes());
        String encryptedHex2 = DatatypeConverter.printHexBinary(encrypted2);
        //..but if we encrypt again with the same AES object instance the random IV will be held and we get the same result
        assertThat("AESGC.encryptAndMerge 2", encryptedHex2, equalTo(encryptedHex2));
    }

    @Test
    public void testEncryptStream() throws Exception {
        String toEncrypt = "Stream uses always a random salt and a random iv!";
        char[] password = "12345".toCharArray();
        try (InputStream in = new ByteArrayInputStream(toEncrypt.getBytes("UTF-8"));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            AESGC.encryptStream(password, in, out);
            byte[] result = out.toByteArray();
            assertThat("EncryptionStream Length!", DatatypeConverter.printHexBinary(result).length(), is(192));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testDecryptStream() throws Exception {
        String toEncrypt = "This could also be read from an FileInputStream!";
        char[] password = "PassWoord!!".toCharArray();
        byte[] encryptedBytes = DatatypeConverter.parseHexBinary("91B6D0D2FD474269ED180DF93FF45C42E921B87EA98CD90F488EAE71453191857040A7973C2374297CEBB5F07F675284A3646FADF3F35723DD152BC8526E5B8C18452D4DFE757E6AEC5724F4888D8EE0257E80877F048C175C8DF89DC196CAB7");
        try (InputStream inD = new ByteArrayInputStream(encryptedBytes);
             ByteArrayOutputStream outD = new ByteArrayOutputStream()) {
            AESGC.decryptStream(password, inD, outD);
            assertThat("En-De-Cryption failed!", new String(outD.toByteArray()), equalTo(toEncrypt));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testEncrypt2Base64AndViceVersa() throws Exception {
        char[] password = "t.c.m.j".toCharArray();
        String base64 = AESGC.encrypt2Base64(password, "ThisIsSecretData!".getBytes());
        String back = AESGC.decryptBase64(password, base64);
        assertThat("AESGC.encryptAndMerge", back, equalTo("ThisIsSecretData!"));
    }

    @Test
    public void testExtractSalt() throws Exception {
        byte[] input = DatatypeConverter.parseHexBinary("F83D5D6E3BFE96164E06D532FE713116E1453C8CCD165720241459FBE6A76B1E6F71703E3EF06E2A715041DEFCC846F4");
        String expected = "F83D5D6E3BFE96164E06D532FE713116";
        byte[] bytes = new AESGC().extractSalt(input);
        String result = DatatypeConverter.printHexBinary(bytes);
        assertThat("AESGC.extractSalt", result, equalTo(expected));
    }

    @Test
    public void testExtractIV() throws Exception {
        byte[] input = DatatypeConverter.parseHexBinary("F83D5D6E3BFE96164E06D532FE713116E1453C8CCD165720241459FBE6A76B1E6F71703E3EF06E2A715041DEFCC846F4");
        String expected = "E1453C8CCD165720241459FBE6A76B1E";
        byte[] bytes = new AESGC().extractIV(input);
        String result = DatatypeConverter.printHexBinary(bytes);
        assertThat("AESGC.extractIV", result, equalTo(expected));
    }

    @Test
    public void testExtractEncryptedData() throws Exception {
        byte[] input = DatatypeConverter.parseHexBinary("F83D5D6E3BFE96164E06D532FE713116E1453C8CCD165720241459FBE6A76B1E6F71703E3EF06E2A715041DEFCC846F4");
        String expected = "6F71703E3EF06E2A715041DEFCC846F4";
        byte[] bytes = new AESGC().extractEncryptedData(input);
        String result = DatatypeConverter.printHexBinary(bytes);
        assertThat("AESGC.extractEncryptedData", result, equalTo(expected));
    }

    @Test
    public void testGetPwdIterations() throws Exception {
        AESGC aes = new AESGC();
        assertThat("default password iterations", aes.getPwdIterations(), is(AESGC.Defaults.DEFAULT_ITERATIONS));
    }

    @Test
    public void testSetPwdIterations() throws Exception {
        AESGC aes = new AESGC(128, 10, 1977);
        assertThat("1977 password iterations", aes.getPwdIterations(), is(1977));
        aes.setPwdIterations(1558);
        assertThat("1558 password iterations", aes.getPwdIterations(), is(1558));
    }

    @Test
    public void testProviderNotAvailable() throws Exception {
        //This test emulates if the AES provider is not available on the current installation by
        //asking for null instead of 'AES' (internally it resets a private constant field value)
        AESGC aes = new AESGC();
        Field field = aes.getClass().getDeclaredField("CIPHER_TRANSFORM_AES");
        field.setAccessible(true);
        field.set(null, null); //set value to null
        Method isKeySizeAllowed = aes.getClass().getDeclaredMethod("isKeySizeAllowed", new Class[]{int.class});
        assertThat("Check null instead of AES key size", isKeySizeAllowed.invoke(aes, AESGC.Defaults.KEY_SIZE_128_BITS), is(false));
        field.set(null, "AES"); //set value back to 'AES' !! totally necessary!
    }

    @Test(expected = IllegalStateException.class)
    public void testWrongSaltSizeUsage() throws Exception {
        //This test initialises the AES object with the default salt size (16 bytes)
        AESGC encryptor = new AESGC();
        //trying to use a key of another salt size an exception should raise
        byte[] salt = AESGC.generateSalt(32);
        SecretKey key = encryptor.generateKey("12345".toCharArray(), salt); //<< Exception!
        assertThat("This line should not been reached!", key, nullValue());
    }

    @Test(expected = javax.crypto.BadPaddingException.class)
    public void testDifferentBlockSizeUsage() throws Exception {
        AESGC encryptor128 = new AESGC(AESGC.Defaults.KEY_SIZE_128_BITS, AESGC.Defaults.DEFAULT_SALT_SIZE_CBC, AESGC.Defaults.DEFAULT_ITERATIONS);
        byte[] data2Encrypt = "Feistel and Coppersmith rule. Sixteen rounds and one hell of an avalanche!".getBytes();
        char[] password = "whatever".toCharArray(); //passwords should be held in character arrays, not String's!
        byte[] salt = encryptor128.generateSalt();
        SecretKey key = encryptor128.generateKey(password, salt);
        byte[] encryptedA = encryptor128.encryptAndMerge(key, salt, data2Encrypt);
        Crypto.removeCryptographyRestrictions();
        AESGC decryptor192 = new AESGC(AESGC.Defaults.KEY_SIZE_192_BITS, AESGC.Defaults.DEFAULT_SALT_SIZE_CBC, AESGC.Defaults.DEFAULT_ITERATIONS);
        byte[] decrypted = decryptor192.decryptMergedData(password, encryptedA);
        assertThat("It should not be possible to encrypt with 128 and decrypt with 192 bit mode!", decrypted, not(equalTo(data2Encrypt)));
    }


}
