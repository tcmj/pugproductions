package com.tcmj.common.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import com.tcmj.common.text.RandomStrings;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;


/**
 * Usage of class {@link com.tcmj.common.crypto.AES }
 * <pThe benefit of the AES class is the merging function which simplifies handling of the key, salt, initialisation vector and the encrypted data.</p>
 * <p>There's a extended debugging mode which can be activated using jvm parameter: 'java.security.debug'</p>
 */
public class AESUsage {

    /** Helper method to test if input data is the same after encryption - decryption. */
    private static void encryptDecrypt(String text) throws Exception {
        char[] password = "avzh5F3§v bfh%ASt35!".toCharArray();
        AES pbe = new AES();
        byte[] salt = pbe.generateSalt();
        String result = new String(pbe.decryptMergedData(password, pbe.encryptAndMerge(pbe.generateKey(password, salt), salt, text.getBytes("UTF-8"))), "UTF-8");
        System.out.println(result);
        assertThat("Equality Problem for: " + text, result, equalTo(text));
    }

    /**
     * Simple example which can be used to encrypt and decrypt some data.
     * <p>Steps:
     * <ol>
     * <li>Creation of a aes key object</li>
     * <li>The data encryption process (producing merged data)</li>
     * <li>Simplified decryption of the previously data</li>
     * </ol></p>
     * <p>It is only necessary to keep the password secret and know the initial parameters (default values using the empty constructor of the AES class)!</p>
     * <p>Defaults are AES in 128 bit mode using 65536 password iterations at key generation</p>
     */
    @Test
    public void normalUsage() throws Exception {
        //we want to encrypt following data....we can encrypt anything which can be converted to a byte array
        byte[] data2Encrypt = "This is our secret data which can be any bytes we want to encrypt!".getBytes();
        char[] password = "aG§s5 Srt234!MyP assw0rd!!".toCharArray(); //passwords should be held in character arrays, not String's!

        //we start by creating an AES object...(the empty constructor is defaulting to some initial parameters, eg. 128 bit mode)
        AES encryptor = new AES();
        //first we need a salt... we choose to generate a new random one
        byte[] salt = encryptor.generateSalt();
        //next we create our AES key object using our secret password and the previously created salt
        SecretKey key = encryptor.generateKey(password, salt);

        //apply encryption producing extended cipher data
        byte[] encryptedA = encryptor.encryptAndMerge(key, salt, data2Encrypt);

        //apply decryption
        AES decryptor = new AES(); //(we simulate a separate session and use NOT the same AES object for encryption and decryption)
        byte[] decrypted = decryptor.decryptMergedData(password, encryptedA);
        //we only have to convert our byte array back to String:
        System.out.println("Data: '" + new String(decrypted) + "'");

        //proof:
        assertThat(decrypted, equalTo(data2Encrypt));
    }

    /**
     * Extended example to encrypt and decrypt with a bunch of customized values.
     * <p>We want:
     * <ul>
     * <li>AES 256 bit which usually assumes the installation of JCE</li>
     * <li>We some larger data to en-/decrypt, because we can</li>
     * <li>A predefined value of 100 password iterations at key generation</li>
     * <li>A predefined salt size of 32 bytes (twice the size of the default)</li>
     * <li>The default handling of the IV - a random one will be created (just to mention the initialisation vector)</li>
     * </ul></p>
     * <p>Steps:
     * <ol>
     * <li>Unlocking the 256 bit mode {@link Crypto#removeCryptographyRestrictions()}</li>
     * <li>Creation of a key object</li>
     * <li>The data encryption process (producing merged data)</li>
     * <li>Simplified decryption of the previously data</li>
     * </ol></p>
     * <p>It is only necessary to keep the password secret and know the initial parameters (customized values set by the constructor of the AES class)!</p>
     */
    @Test
    public void extendedUsage() throws Exception {

        //Usually we need the JCE installation to unlock AES 256 ! Bypassing the installation we can use our Crypt class:
        Crypto.removeCryptographyRestrictions();

        //Our large test data and high security password:
        String ourData = StringUtils.repeat("I will not use german umlauts like 'ö' again!", System.lineSeparator(), 20000);
        byte[] data2Encrypt = ourData.getBytes();
        char[] password = "xq{3$s!2!C4,/^FsyPTEGw@-RR{pT)ZSPF'7`K,]>yA(P*gWJ,;G=!<HdJ{Z&6s>rf49tnQ!<]<cNS`Z@,:NuG\\F*6A*v>,.KCTp!G`N>Nwjr^-6^!FE3MGLY^GFG.N\\L\"RG)-fMmQ~mC>ZG\\HWceK!`mfYQue%ZL^!~Dd)bfx?s+<59PnGKh3&*~\\G#=U?f$+Ww*?Vv<MGnB$N@[.ayCWn5;-WY,\\87@;7}:5q:f)yA`tJ!Ba3Aj=%URg(Rj-}y".toCharArray();
        System.out.println("We have        : " + ourData.length() + " letters in " + data2Encrypt.length + " bytes! And a powerful password of " + password.length + " chars!");

        //we want to use 100 password iterations for our key and a custom-sized salt of 32 bytes
        final int iterations = 100;
        final int saltSizeInBytes = 32;

        //now we can do the initialisation of our AES object:
        AES encryptor = new AES(AES.Defaults.KEY_SIZE_256_BITS, saltSizeInBytes, iterations);
        System.out.println("AES object     : " + encryptor);

        //we have to provide the 32 byte salt (random or fixed ...its our decision)
        byte[] salt = AES.generateSalt(32);
        System.out.println("Salt           : " + DatatypeConverter.printHexBinary(salt));

        //having salt we can generate the key:
        SecretKey key = encryptor.generateKey(password, salt);
        System.out.println("Key            : " + DatatypeConverter.printHexBinary(key.getEncoded()));

        //apply encryption producing a byte array containing salt+iv+data
        byte[] encrypted = encryptor.encryptAndMerge(key, salt, data2Encrypt);
        System.out.println("Encryption     : " + StringUtils.abbreviate(DatatypeConverter.printHexBinary(encrypted), 120));

        //starting over again simulating another jvm in another world at another time...
        AES decryptor = new AES(AES.Defaults.KEY_SIZE_256_BITS, saltSizeInBytes, iterations); //<-- important initial values!

        //apply the magically easy decryption function which does all the hard job:
        byte[] decrypted = decryptor.decryptMergedData(password, encrypted);
        System.out.println("Encryption     : " + StringUtils.abbreviate(new String(decrypted), 48));

        //check the result:
        assertThat("we want exactly the same bytes back!", decrypted, equalTo(data2Encrypt));
        //for security reason it is only allowed put the salt and the iv in public - neither the key nor the password!
        assertThat("The key must not be in the output data!", StringUtils.containsIgnoreCase(DatatypeConverter.printHexBinary(encrypted), DatatypeConverter.printHexBinary(key.getEncoded())), is(false));
        assertThat("The password must not be in the output data!", StringUtils.containsIgnoreCase(DatatypeConverter.printHexBinary(encrypted), DatatypeConverter.printHexBinary(new String(password).getBytes())), is(false));

    }

    /**
     * Extended example to encrypt and decrypt with fixed values.
     * <p>We want:
     * <ul>
     * <li>AES 192 bit</li>
     * <li>A predefined value of 1234 password iterations at key generation</li>
     * <li>A predefined and fixed salt value</li>
     * <li>A predefined and fixed initialisation vector (IV)</li>
     * </ul></p>
     * <p>Steps:
     * <ol>
     * <li>Unlocking the 256 bit mode {@link Crypto#removeCryptographyRestrictions()}</li>
     * <li>Creation of a key object</li>
     * <li>The data encryption process (producing merged data)</li>
     * <li>Simplified decryption of the previously data</li>
     * </ol></p>
     * <p>It is only necessary to keep the password secret and know the initial parameters (customized values set by the constructor of the AES class)!</p>
     */
    @Test
    public void fixedValueUsage() throws Exception {

        //Usually we need the JCE installation to unlock AES 256 ! Bypassing the installation we can use our Crypt class:
        Crypto.removeCryptographyRestrictions();

        //Our test data and high security password:
        byte[] data2Encrypt = "Encryption works. Properly implemented strong crypto systems are one of the few things that you can rely on. Unfortunately, endpoint security is so terrifically weak that NSA can frequently find ways around it.".getBytes();
        char[] password = "Fh^#2LMSBKC42J4pRf@FTZt#Kz4HBJ".toCharArray();

        //we want to use 1234 password iterations for our key and the default salt size of 16 bytes
        final int iterations = 1234;

        //do the initialisation of our AES object:
        AES encryptor = new AES(AES.Defaults.KEY_SIZE_192_BITS, AES.Defaults.DEFAULT_SALT_SIZE, iterations);
        System.out.println("AES object     : " + encryptor);

        //we have to provide the fixed salt
        byte[] salt = DatatypeConverter.parseHexBinary("0741DFD00B7C1A186A50B4D9DD0C3FE2");

        //use a custom Initialisation Vector (in case that the iv is predefined)
        byte[] iv = DatatypeConverter.parseHexBinary("18FB095986F4AB37CCF77BF3C4C8A3D2");
        IvParameterSpec iV = new IvParameterSpec(iv);

        //having salt we can generate the key:
        SecretKey key = encryptor.generateKey(password, salt);
        System.out.println("Key            : " + DatatypeConverter.printHexBinary(key.getEncoded()));

        //apply encryption producing a byte array containing salt+iv+data
        byte[] encrypted = encryptor.encryptAndMerge(key, salt, iV, data2Encrypt);
        System.out.println("Encryption     : " + DatatypeConverter.printHexBinary(encrypted));

        //starting over again simulating another jvm in another world at another time...
        AES decryptor = new AES(AES.Defaults.KEY_SIZE_192_BITS, AES.Defaults.DEFAULT_SALT_SIZE, iterations); //<-- important initial values!

        //apply the magically easy decryption function which does all the hard job:
        byte[] decrypted = decryptor.decryptMergedData(password, encrypted);
        System.out.println("Encryption     : " + new String(decrypted));

        //check the result:
        assertThat("we want exactly the same bytes back!", decrypted, equalTo(data2Encrypt));
        assertThat("The key must not be in the output data!", StringUtils.containsIgnoreCase(DatatypeConverter.printHexBinary(encrypted), DatatypeConverter.printHexBinary(key.getEncoded())), is(false));
        assertThat("The salt must be in the output data!", StringUtils.containsIgnoreCase(DatatypeConverter.printHexBinary(encrypted), "0741DFD00B7C1A186A50B4D9DD0C3FE2"), is(true));
        assertThat("The iv must be in the output data!", StringUtils.containsIgnoreCase(DatatypeConverter.printHexBinary(encrypted), "18FB095986F4AB37CCF77BF3C4C8A3D2"), is(true));
        assertThat("Whole merged data must be the same forever!", DatatypeConverter.printHexBinary(encrypted), equalTo("0741DFD00B7C1A186A50B4D9DD0C3FE218FB095986F4AB37CCF77BF3C4C8A3D25E379F1970203858D84402663B29788F231215A0FD2B82902D475A92F14AA2121858DC01ECE0CB623B218460285A3A680462D73E4B30E6BF919A7CDF02D2C1308DC498B4DA08E159A27D0F4933D8F0A1005B0148BB50EA3ADF7554D1611B8ED89C4068C66A50BD5F86D2020B7F26E3468A491709C33DC03D7854CAD4861FC4FFA6298FBB35698F4AC6DE72DC012205D3290635BFC4B42848A99E0F3A0B2F04ABFE081F45BA6CA242C7A4E3AD6F3BDD2193CBAA68FF7AC0D552B1CC878FA65E1A59314C5055674B4E7E67C8DC7CAB991D958F33FBCC8CA415973FD318EA0892B1"));

    }

    @Test
    public void enableAES256BitKeySize() {
        //initially we cannot use 256 bit as key size:
        assertThat("Check AES key size 256", AES.isKeySizeAllowed(AES.Defaults.KEY_SIZE_256_BITS), is(false)); //valid but locked

        //Extended Java installation (JCE jurisdiction policy files)
        Crypto.removeCryptographyRestrictions();

        //..now we can also use 192 and 256 bit key size for AES
        assertThat("Check AES key size 192", AES.isKeySizeAllowed(192), is(true));
        assertThat("Check AES key size 256", AES.isKeySizeAllowed(256), is(true));
    }

    /** We want to test some special cases to ensure that we get exactly the same after decrypting our encrypted data. */
    @Test
    public void encryptDecrypt() throws Exception {
        encryptDecrypt("a");    //single lower case char should stay the same
        encryptDecrypt("A");    //..same test with a single upper case char
        encryptDecrypt("Just some random Text and Numbers 1 2 3 4");
        encryptDecrypt("AVeryLongText " + StringUtils.repeat(new RandomStrings().randomWordCapitalized(500), 100));
        encryptDecrypt("Special Characters: !\"§$%&/()=?`´ 28°C <> || ;,:.-_ *' ÖÜÄöüä~");
        encryptDecrypt("multiline\r\nmultiline\r\nmultiline\nmultiline\n");
    }

    @Test
    public void testDecrypt() throws Exception {
        String ciphertext = "FVAZTZoZelJ5muNhE96TCmiQZhwgFuZvkrwxwo8PqOtL8q79BSxTj5WGgXJ_p5Zqkkpu8vABrCrK_XKevuOynT7PkD-QQzxu2_tF7KSjeoa53XaW5Pw2GWKuP3-YZ9wid4hDHwzrVw_QmlyS5U6i_sjoFQIeETZkhC6t-vJQdn0="; //PBKDF2WithHmacSHA512
        char[] password = "avzh5F3§v bfh%ASt35!".toCharArray();
        byte[] cipherbytes = Crypto.Base64.decode(ciphertext);
        AES aes = new AES(256, 16, AES.Defaults.DEFAULT_ITERATIONS);
        byte[] bytes = aes.decryptMergedData(password, cipherbytes);
        String decrypt = new String(bytes);
        System.out.println("Decrypted Text: " + decrypt);
        String wewant = "This is the text we want to encrypt! The more i write the larger the encryption will get!";
        assertThat("Equality!", decrypt, equalTo(wewant));
    }


    @Test
    public void testLoop() throws Exception {
        StopWatch watch = new StopWatch();
        watch.start();
        char[] password = "a89))((zz66".toCharArray();
        RandomStrings rand = new RandomStrings();
        for (int i = 0; i <= 3; i++) {
            String word = rand.randomWordCapitalized(i);
            String base = AES.encrypt2Base64(password, word.getBytes());
            //System.out.println("Base64: " + base + " Plain: " + word);
        }
        watch.stop();
        System.out.println("Time: " + watch.toString());
    }

    @Test
    public void testPerformantEncrpytionAndDecryption() throws Exception {
        //encryptAndMerge mass data
        StopWatch watch = new StopWatch();
        RandomStrings rand = new RandomStrings();
        int loops = 1000;
        Map<String, String> datastore = new HashMap<>();
        //given:
        char[] password = "our!Pass3ord!!!".toCharArray();
        AES aes = new AES();

        System.out.println("Start encrypting " + loops + " pieces using the same key but different IVs");
        watch.start();
        byte[] salt = aes.generateSalt();
        SecretKey crypKey = aes.generateKey(password, salt);

        for (int i = 1; i <= loops; i++) {
            String word = rand.randomWordCapitalized(100);
            byte[] encrypt = aes.encryptAndMerge(crypKey, salt, word.getBytes());
            String hex = DatatypeConverter.printHexBinary(encrypt);
            datastore.put(word, hex);
        }
        watch.stop();
        System.out.println("Encryption Time: " + watch.toString() + " (of " + loops + " loops)");

        System.out.println("Start decrypting " + loops + " pieces using the same key but individual IV");
        watch.reset();
        watch.start();
        AES aes256 = new AES();

        SecretKey key = null;

        for (Map.Entry<String, String> entry : datastore.entrySet()) {
            byte[] data = Crypto.hexStringToByteArray(entry.getValue());
            if (key == null) {
                key = aes256.generateKey(password, aes256.extractSalt(data));
            }

            byte[] bytes = aes256.decrypt(key, aes256.extractIV(data), aes256.extractEncryptedData(data));
            String result = new String(bytes, "UTF-8");
            assertThat(result, equalTo(entry.getKey()));

        }
        watch.stop();
        System.out.println("Decryption Time: " + watch.toString() + " (of " + loops + " loops)"); //03:30 - loop:1000

    }

    @Test
    public void testStreamEncryption() throws Exception {

        String toEncrypt = "This could also be read from an FileInputStream!";
        char[] password = "PassWoord!!".toCharArray();

        byte[] result = null;
        try (InputStream in = new ByteArrayInputStream(toEncrypt.getBytes("UTF-8"));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            AES.encryptStream(password, in, out);
            result = out.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        }

        try (InputStream inD = new ByteArrayInputStream(result);
             ByteArrayOutputStream outD = new ByteArrayOutputStream()) {
            AES.decryptStream(password, inD, outD);
            assertThat("En-De-Cryption failed!", new String(outD.toByteArray()), equalTo(toEncrypt));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Test
    public void testSameSaltAndIvProducesSameCipherText() throws Exception {
        System.out.println("Default encoding: " + Charset.defaultCharset());
        char[] password = "super space containing password".toCharArray();
        String plain = "Claudia";
        AES aes = new AES();
        IvParameterSpec iv = AES.generateIV();
        byte[] salt = aes.generateSalt();
        SecretKey key = aes.generateKey(password, salt);
        System.out.println("Encrypting with same key: " + DatatypeConverter.printHexBinary(key.getEncoded()) + " and salt: " + DatatypeConverter.printHexBinary(salt) + " and iv: " + DatatypeConverter.printHexBinary(iv.getIV()));
        for (int i = 1; i <= 5; i++) {
            byte[] encrypted = aes.encryptAndMerge(key, salt, iv, plain.getBytes());
            String plainAgain = new String(aes.decryptMergedData(password, encrypted));
            System.out.println(DatatypeConverter.printHexBinary(encrypted) + " Plain: " + plainAgain);
            assertThat(plainAgain, equalTo(plain));
        }
    }

}
