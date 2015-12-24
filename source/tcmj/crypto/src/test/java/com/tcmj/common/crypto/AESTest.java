package com.tcmj.common.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

/**
 * Tests of class {@link com.tcmj.common.crypto.AES }
 * <p>There's a extended debugging mode which can be activated using jvm parameter: 'java.security.debug'</p>
 */
public class AESTest {

    @Test
    public void testConstructorValid() throws Exception {
        assertThat("128 bit", new AES(128, 1, 1), notNullValue());
        assertThat("192 bit", new AES(192, 1, 1), notNullValue());
        assertThat("256 bit", new AES(256, 1, 1), notNullValue());
    }

    @Test(expected = java.lang.RuntimeException.class)
    public void testConstructorInvalidBitSize() throws Exception {
        new AES(100, 16, 1000);
    }

    @Test(expected = java.lang.RuntimeException.class)
    public void testConstructorInvalidSaltSize() throws Exception {
        new AES(128, 0, 100);
    }

    @Test(expected = java.lang.RuntimeException.class)
    public void testConstructorInvalidIterationCount() throws Exception {
        new AES(128, 16, 0);
    }

    @Test
    public void testToString() throws NoSuchPaddingException, NoSuchAlgorithmException {
        Assert.assertTrue(StringUtils.startsWith(new AES().toString(), "AES/CBC/PKCS5Padding/128Bit/PBKDF2WithHmacSHA512/"));
        Assert.assertTrue(StringUtils.startsWith(new AES(AES.Defaults.KEY_SIZE_256_BITS, 8, 999).toString(), "AES/CBC/PKCS5Padding/256Bit/PBKDF2WithHmacSHA512/"));
    }

    @Test
    public void testGetKeySize() throws Exception {
        assertThat("default key size 128 bit", new AES().getKeySize(), is(AES.Defaults.KEY_SIZE_128_BITS));
        assertThat("key size 192 bit", new AES(AES.Defaults.KEY_SIZE_192_BITS, 8, 10).getKeySize(), is(AES.Defaults.KEY_SIZE_192_BITS));
        assertThat("key size 256 bit", new AES(AES.Defaults.KEY_SIZE_256_BITS, 8, 10).getKeySize(), is(AES.Defaults.KEY_SIZE_256_BITS));
    }

    @Test
    public void testGetSaltSize() throws Exception {
        assertThat("default salt size 16 byte", new AES().getSaltSize(), is(AES.Defaults.DEFAULT_SALT_SIZE));
        assertThat("salt size 8 byte", new AES(128, 8, 10).getSaltSize(), is(8));
        assertThat("salt size 55 byte", new AES(128, 55, 10).getSaltSize(), is(55));
    }

    @Test
    public void testGetIVSize() throws Exception {
        assertThat("fixed iv size 16 byte", new AES().getIVSize(), is(16));
        assertThat("iv size using custom constructor", new AES(256, 8, 10).getIVSize(), is(16));
    }

    @Test
    public void testIsKeySizeAllowed() throws Exception {
        //Standard Java installation (Standard JCE)
        assertThat("Check AES key size 128", AES.isKeySizeAllowed(AES.Defaults.KEY_SIZE_128_BITS), is(true)); //this is the only allowed one by default
        assertThat("Check AES key size 192", AES.isKeySizeAllowed(AES.Defaults.KEY_SIZE_192_BITS), is(false)); //valid but locked
        assertThat("Check AES key size 256", AES.isKeySizeAllowed(AES.Defaults.KEY_SIZE_256_BITS), is(false)); //valid but locked
        //Hack to emulate Extended Java installation (JCE jurisdiction policy files)
        Crypto.removeCryptographyRestrictions();
        //..now we can also use 192 and 256 bit key size for AES
        assertThat("Check AES key size 128", AES.isKeySizeAllowed(128), is(true));
        assertThat("Check AES key size 192", AES.isKeySizeAllowed(192), is(true));
        assertThat("Check AES key size 256", AES.isKeySizeAllowed(256), is(true));

        //Error case ... throwing no exception
        assertThat("Check invalid AES key size 333", AES.isKeySizeAllowed(333), is(false));

    }

    @Test
    public void testGenerateSalt() throws Exception {
        assertThat("default 16 byte salt", new AES().generateSalt().length, is(16));
        assertThat("16 byte salt", new AES(128, 20, 100).generateSalt().length, is(20));
        assertThat("should create different salts", DatatypeConverter.printHexBinary(new AES().generateSalt()), not(equalTo(DatatypeConverter.printHexBinary(new AES().generateSalt()))));
    }

    @Test
    public void testGenerateSaltWithSize() throws Exception {
        assertThat("8 byte salt", AES.generateSalt(8).length, is(8));
        assertThat("16 byte salt", AES.generateSalt(16).length, is(16));
        assertThat("should create different salts", DatatypeConverter.printHexBinary(AES.generateSalt(16)), not(equalTo(DatatypeConverter.printHexBinary(AES.generateSalt(16)))));
    }

    @Test
    public void testGenerateIV() throws Exception {
        IvParameterSpec ivParameterSpec = AES.generateIV();
        assertThat("generateIV() should return non null IvParameterSpec obj", ivParameterSpec, notNullValue());
        assertThat("generateIV() should contain non null byte array", ivParameterSpec.getIV(), notNullValue());
        assertThat("generateIV() 16 bytes length", ivParameterSpec.getIV().length, is(16));
        assertThat("should create different ivs", DatatypeConverter.printHexBinary(AES.generateIV().getIV()), not(equalTo(DatatypeConverter.printHexBinary(AES.generateIV().getIV()))));
    }

    @Test
    public void testGenerateKey() throws Exception {
        AES aes = new AES(); //128bit
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
        AES aes = new AES(); //128bit
        char[] password = "Kindergarten".toCharArray();
        byte[] salt = aes.generateSalt();
        int iterations = 8864; //performance!
        SecretKey key = aes.generateKey(password, salt, iterations);
        assertThat("generateKey(char[],byte[],int) should not return null", key, notNullValue());
        assertThat("generateKey(char[],byte[],int) should return AES key", key.getAlgorithm(), equalTo("AES"));
        assertThat("generateKey(char[],byte[],int) should not be destroyed", key.isDestroyed(), is(false));
        SecretKey key2 = new AES().generateKey(password, salt, iterations);
        assertThat("should create same ", DatatypeConverter.printHexBinary(key.getEncoded()), equalTo(DatatypeConverter.printHexBinary(key2.getEncoded())));
    }

    @Test
    public void testGetInitialisationVector() throws Exception {
        AES aes = new AES();
        assertThat("getInitialisationVector should never return null", aes.getInitialisationVector(), notNullValue());
        //if no encryption has been made, the method should return always new random values!
        byte[] iV = aes.getInitialisationVector();
        byte[] iV2 = aes.getInitialisationVector();
        assertThat("should create different ivs 1 not 2", DatatypeConverter.printHexBinary(iV), not(equalTo(DatatypeConverter.printHexBinary(iV2))));
        assertThat("should create different ivs 2", DatatypeConverter.printHexBinary(new AES().getInitialisationVector()), not(equalTo(DatatypeConverter.printHexBinary(new AES().getInitialisationVector()))));
    }

    @Test
    public void testGetInitialisationVectorSame() throws Exception {
        /* for the same encryption the same IV should be returned by getInitialisationVector() ! ! ! */
        AES aes = new AES(128, 48, 1);
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
    public void testDecryptMergedData() throws Exception {
        char[] password = "dg43zfh$FDD!".toCharArray();
        String text = "we want this to be encrypted!";
        byte[] encrypted = DatatypeConverter.parseHexBinary("FD3A39C36685DDF6FC997F7124732689D579D1CEAD5432548DCCB6399D1AAF1B1B49E9652B3C3844DD016FDDD10CCE43F2EA70EEAA669D705F9387BE9AB49C7A");
        assertThat("Decrypting: " + text, new String(new AES().decryptMergedData(password, encrypted)), equalTo(text));
    }

    @Test
    public void testDecryptWithKey() throws Exception {
        /* decrypt method which takes a key as argument. */
        AES decryptor = new AES();
        byte[] mySalt = DatatypeConverter.parseHexBinary("6C87628C44B009B69190651142F8E075");
        SecretKey myKey = decryptor.generateKey("verySecretPassword".toCharArray(), mySalt);
        byte[] iV = DatatypeConverter.parseHexBinary("2F2E72ACA494E8B045D25F2DC317D6FA");
        byte[] cipherData = DatatypeConverter.parseHexBinary("F9D5D173F90AC3DE0F976E3CAE0E9DBFE906F6D1BC5FBC1022582FEC1AD65E24276003EB20E69E77DB36BD40A8AB52A04A62B7EE7554EA5529611ADCF6E20E4A");
        byte[] decrypt = decryptor.decrypt(myKey, iV, cipherData);
        String result = new String(decrypt);
        assertThat("AES.decrypt(Key, IV, CipherData)", result, equalTo("if you can read this you have successfully decrypted my brain!"));
    }

    @Test
    public void testDecrypt() throws Exception {
        /* decrypt method which builds the key internally and takes all arguments needed to do that. */
        AES decryptor = new AES(128, 48, 500);
        byte[] mySalt = DatatypeConverter.parseHexBinary("4561EB6209C7EE43BAC6204DD0ABAF929A8D7A07FE04537D266DA20A8E3A8C434A25819348A88B0898150EB686E0DF2A");
        byte[] iV = DatatypeConverter.parseHexBinary("B30B7F05409E0F1308DDCAB27F75C9B6");
        byte[] cipherData = DatatypeConverter.parseHexBinary("8E44FC9B118FAAAEDDABD4BAC22FA5D1F17DCF8FAD4EDEC6047C0D8795E664BE");
        byte[] decrypt = decryptor.decrypt("t.c.m.j".toCharArray(), mySalt, iV, cipherData);
        assertThat("AES.decrypt(Key, IV, CipherData)", new String(decrypt), equalTo("TopSecretThisTimeWith!$%&/()"));
    }

    @Test
    public void testEncryptAndMerge() throws Exception {
        /* same input parameters produce always same output parameters!*/
        AES aes = new AES();
        byte[] salt = DatatypeConverter.parseHexBinary("6C87628C44B009B69190651142F8E075");
        byte[] iV = DatatypeConverter.parseHexBinary("B30B7F05409E0F1308DDCAB27F75C9B6");
        SecretKey key = aes.generateKey("t.c.m.j".toCharArray(), salt);
        IvParameterSpec iv = new IvParameterSpec(iV);
        byte[] encrypted = aes.encryptAndMerge(key, salt, iv, "Encrypt".getBytes());
        assertThat("AES.encryptAndMerge", DatatypeConverter.printHexBinary(encrypted), equalTo("6C87628C44B009B69190651142F8E075B30B7F05409E0F1308DDCAB27F75C9B6BF58EC6D318837E47FB764DD5E6291E8"));
    }

    @Test
    public void testEncryptAndMergeWithoutIv() throws Exception {
         /* we encrypt (..and merge) with a random IV!*/
        AES aes = new AES();
        byte[] salt = DatatypeConverter.parseHexBinary("6C87628C44B009B69190651142F8E075");

        SecretKey key = aes.generateKey("t.c.m.j".toCharArray(), salt);
        byte[] encrypted = aes.encryptAndMerge(key, salt, "Encrypt".getBytes());
        String encryptedHex1 = DatatypeConverter.printHexBinary(encrypted);
        //we cannot define the expected result because of the random IV used!
        assertThat("AES.encryptAndMerge 1", encryptedHex1, not(equalTo("6C87628C44B009B69190651142F8E075B30B7F05409E0F1308DDCAB27F75C9B6BF58EC6D318837E47FB764DD5E6291E8")));

        byte[] encrypted2 = aes.encryptAndMerge(key, salt, "Encrypt".getBytes());
        String encryptedHex2 = DatatypeConverter.printHexBinary(encrypted2);
        //..but if we encrypt again with the same AES object instance the random IV will be held and we get the same result
        assertThat("AES.encryptAndMerge 2", encryptedHex2, equalTo(encryptedHex2));
    }

    @Test
    public void testEncryptStream() throws Exception {
        String toEncrypt = "Stream uses always a random salt and a random iv!";
        char[] password = "12345".toCharArray();
        try (InputStream in = new ByteArrayInputStream(toEncrypt.getBytes("UTF-8"));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            AES.encryptStream(password, in, out);
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
            AES.decryptStream(password, inD, outD);
            assertThat("En-De-Cryption failed!", new String(outD.toByteArray()), equalTo(toEncrypt));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testEncrypt2Base64AndViceVersa() throws Exception {
        char[] password = "t.c.m.j".toCharArray();
        String base64 = AES.encrypt2Base64(password, "ThisIsSecretData!".getBytes());
        String back = AES.decryptBase64(password, base64);
        assertThat("AES.encryptAndMerge", back, equalTo("ThisIsSecretData!"));
    }

    @Test
    public void testExtractSalt() throws Exception {
        byte[] input = DatatypeConverter.parseHexBinary("F83D5D6E3BFE96164E06D532FE713116E1453C8CCD165720241459FBE6A76B1E6F71703E3EF06E2A715041DEFCC846F4");
        String expected = "F83D5D6E3BFE96164E06D532FE713116";
        byte[] bytes = new AES().extractSalt(input);
        String result = DatatypeConverter.printHexBinary(bytes);
        assertThat("AES.extractSalt", result, equalTo(expected));
    }

    @Test
    public void testExtractIV() throws Exception {
        byte[] input = DatatypeConverter.parseHexBinary("F83D5D6E3BFE96164E06D532FE713116E1453C8CCD165720241459FBE6A76B1E6F71703E3EF06E2A715041DEFCC846F4");
        String expected = "E1453C8CCD165720241459FBE6A76B1E";
        byte[] bytes = new AES().extractIV(input);
        String result = DatatypeConverter.printHexBinary(bytes);
        assertThat("AES.extractIV", result, equalTo(expected));
    }

    @Test
    public void testExtractEncryptedData() throws Exception {
        byte[] input = DatatypeConverter.parseHexBinary("F83D5D6E3BFE96164E06D532FE713116E1453C8CCD165720241459FBE6A76B1E6F71703E3EF06E2A715041DEFCC846F4");
        String expected = "6F71703E3EF06E2A715041DEFCC846F4";
        byte[] bytes = new AES().extractEncryptedData(input);
        String result = DatatypeConverter.printHexBinary(bytes);
        assertThat("AES.extractEncryptedData", result, equalTo(expected));
    }

    @Test
    public void testGetPwdIterations() throws Exception {
        AES aes = new AES();
        assertThat("default password iterations", aes.getPwdIterations(), is(AES.Defaults.DEFAULT_ITERATIONS));
    }

    @Test
    public void testSetPwdIterations() throws Exception {
        AES aes = new AES(128, 10, 1977);
        assertThat("1977 password iterations", aes.getPwdIterations(), is(1977));
        aes.setPwdIterations(1558);
        assertThat("1558 password iterations", aes.getPwdIterations(), is(1558));
    }
}
