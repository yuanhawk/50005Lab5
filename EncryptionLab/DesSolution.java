import java.io.*;
import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class DesSolution {

    public static final String
            ENCRYPTION = "DES",
            ECB = "ECB",
            BLOCK_SIZE = "PKCS5Padding",
            DIRECTORY = "./EncryptionLab/",
            SHORTTEXT = "shorttext.txt",
            LONGTEXT = "longtext.txt";

    private static final DesSolution desSoln = new DesSolution();


    public static void main(String[] args) {
        String fileName = "shorttext.txt";

        StringBuilder sb = desSoln.initStringFromDir(SHORTTEXT);
        StringBuilder sb2 = desSoln.initStringFromDir(LONGTEXT);
//        System.out.println("Original content: "+ shortText);

        desEncrypt(SHORTTEXT, sb);
        desEncrypt(LONGTEXT,sb2);
    }

    private StringBuilder initStringFromDir(String file) {
        StringBuilder text = new StringBuilder();
        String line;
        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(String.format("%s%s", DIRECTORY, file)));
            while ((line = bufferedReader.readLine()) != null) {
                text.append("\n").append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return text;
    }

    private static void desEncrypt(String file, StringBuilder sb) {
        SecretKey desKey = desSoln.generateSecretKey();

        Cipher desCipher = desSoln.initCipher(ECB, Cipher.ENCRYPT_MODE, desKey);

        byte[] encryptedBytesArray = desSoln.generateEncryptedByte(desCipher, sb.toString());
        if (encryptedBytesArray != null) {
            //TODO: print the length of output encrypted byte[], compare the length of file shorttext.txt and longtext.txt
            System.out.printf("Length of %s is %d\n", file, encryptedBytesArray.length);

            //TODO: Question 3
            System.out.println(new String(encryptedBytesArray));

            //TODO: do format conversion. Turn the encrypted byte[] format into base64format String using Base64
            String base64format = Base64.getEncoder().encodeToString(encryptedBytesArray);

            //TODO: print the encrypted message (in base64format String format)
            System.out.println("\nEncrypted message content:");
            System.out.println(base64format);

            //TODO: create cipher object, initialize the ciphers with the given key, choose decryption mode as DES
            Cipher desCipher2 = desSoln.initCipher(ECB, Cipher.DECRYPT_MODE, desKey);

            //TODO: do decryption, by calling method Cipher.doFinal().
            byte[] decryptedBytesArray = desSoln.generateByte(desCipher2, encryptedBytesArray);
            if (decryptedBytesArray != null) {
                //TODO: do format conversion. Convert the decrypted byte[] to String, using "String a = new String(byte_array);"
                String decryptedString = new String(decryptedBytesArray);

                //TODO: print the decrypted String text and compare it with original text
                System.out.println(decryptedString);
                System.out.println();
            }
        }
    }

    //TODO: generate secret key using DES algorithm
    public SecretKey generateSecretKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    //TODO: create cipher object, initialize the ciphers with the given key, choose encryption mode as DES
    public Cipher initCipher(String type, int mode, SecretKey key) {
        try {
            Cipher desCipher = Cipher.getInstance(String.format("%s/%s/%s", ENCRYPTION, type, BLOCK_SIZE));
            desCipher.init(mode, key);
            return desCipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] generateEncryptedByte(Cipher c, String s) {
        return generateByte(c, s.getBytes());
    }

    public byte[] generateByte(Cipher c, byte[] b) {
        if (c != null && b != null) {
            //TODO: do encryption, by calling method Cipher.doFinal().
            try {
                return c.doFinal(b);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
            }
        }
        return null;
    }


}