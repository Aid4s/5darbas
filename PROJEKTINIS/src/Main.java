import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class Main {
    private static final String AES_KEY_FILE = "aes.key";
    private static final String RSA_PUBLIC_KEY_FILE = "rsa_public.key";
    private static final String RSA_PRIVATE_KEY_FILE = "rsa_private.key";
    private static final String PASSWORDS_FILE = "passwords.csv";
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static SecretKey aesKey;
    private static PublicKey rsaPublicKey;
    private static PrivateKey rsaPrivateKey;

    public static void main(String[] args) throws Exception {
        initializeKeys();
        decryptFileAES(PASSWORDS_FILE, aesKey);

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("Password Manager Menu:");
            System.out.println("1. Save Password");
            System.out.println("2. Find Password");
            System.out.println("3. Update Password");
            System.out.println("4. Delete Password");
            System.out.println("5. Exit");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            switch (choice) {
                case 1:
                    System.out.print("Enter name: ");
                    String name = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String password = scanner.nextLine();
                    System.out.print("Enter URL/application: ");
                    String url = scanner.nextLine();
                    System.out.print("Enter comment: ");
                    String comment = scanner.nextLine();
                    savePassword(name, password, url, comment);
                    break;
                case 2:
                    System.out.print("Enter name to find: ");
                    String nameToFind = scanner.nextLine();
                    String foundPassword = findPassword(nameToFind);
                    if (foundPassword != null) {
                        System.out.println("Password: " + foundPassword);
                    } else {
                        System.out.println("Password not found.");
                    }
                    break;
                case 3:
                    System.out.print("Enter name to update: ");
                    String nameToUpdate = scanner.nextLine();
                    System.out.print("Enter new password: ");
                    String newPassword = scanner.nextLine();
                    updatePassword(nameToUpdate, newPassword);
                    break;
                case 4:
                    System.out.print("Enter name to delete: ");
                    String nameToDelete = scanner.nextLine();
                    deletePassword(nameToDelete);
                    break;
                case 5:
                    encryptFileAES(PASSWORDS_FILE, aesKey);
                    System.exit(0);
                default:
                    System.out.println("Invalid choice. Please try again.");
            }
        }
    }
    //Generuoja  raktus ir ikelia i txt faila AES.key RSA.private.key, jeigu toks failas jau yra nuskaito is jo
    private static void initializeKeys() throws Exception {
        if (Files.exists(Paths.get(AES_KEY_FILE))) {
            aesKey = loadAESKey(AES_KEY_FILE);
        } else {
            aesKey = generateAESKey();
            saveAESKey(aesKey, AES_KEY_FILE);
        }

        if (Files.exists(Paths.get(RSA_PUBLIC_KEY_FILE)) && Files.exists(Paths.get(RSA_PRIVATE_KEY_FILE))) {
            rsaPublicKey = loadRSAPublicKey(RSA_PUBLIC_KEY_FILE);
            rsaPrivateKey = loadRSAPrivateKey(RSA_PRIVATE_KEY_FILE);
        } else {
            KeyPair rsaKeyPair = generateRSAKeyPair();
            rsaPublicKey = rsaKeyPair.getPublic();
            rsaPrivateKey = rsaKeyPair.getPrivate();
            saveRSAKey(rsaPublicKey, RSA_PUBLIC_KEY_FILE);
            saveRSAKey(rsaPrivateKey, RSA_PRIVATE_KEY_FILE);
        }
    }


    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    private static void saveAESKey(SecretKey key, String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(key.getEncoded());
        }
    }

    private static SecretKey loadAESKey(String filePath) throws IOException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        return new SecretKeySpec(keyBytes, "AES");
    }


    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private static void saveRSAKey(Key key, String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(key.getEncoded());
        }
    }

    private static PublicKey loadRSAPublicKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    private static PrivateKey loadRSAPrivateKey(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    private static void encryptFileAES(String filePath, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);

        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(iv);
            fos.write(encryptedBytes);
        }
    }

    private static void decryptFileAES(String filePath, SecretKey key) throws Exception {
        if (!Files.exists(Paths.get(filePath))) return;

        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        byte[] iv = new byte[16];
        System.arraycopy(fileBytes, 0, iv, 0, iv.length);
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParams);

        byte[] encryptedBytes = new byte[fileBytes.length - iv.length];
        System.arraycopy(fileBytes, iv.length, encryptedBytes, 0, encryptedBytes.length);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(decryptedBytes);
        }
    }

    private static void savePassword(String name, String password, String url, String comment) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        byte[] encryptedPassword = cipher.doFinal(password.getBytes());

        try (FileWriter fw = new FileWriter(PASSWORDS_FILE, true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            out.println(name + "," + Base64.getEncoder().encodeToString(encryptedPassword) + "," + url + "," + comment);
        }
    }

    private static List<String[]> readPasswords() throws IOException {
        //sukuriamas masyvas slaptazodziu
        List<String[]> passwords = new ArrayList<>();
        //nuskaito is slaptazodziu failo passwords.csv
        try (BufferedReader br = new BufferedReader(new FileReader(PASSWORDS_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                passwords.add(parts);
            }
        }
        return passwords;
    }

    private static String findPassword(String name) throws Exception {
        List<String[]> passwords = readPasswords();
        for (String[] entry : passwords) {
            if (entry[0].equals(name)) {
                Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
                byte[] decryptedPassword = cipher.doFinal(Base64.getDecoder().decode(entry[1]));
                return new String(decryptedPassword);
            }
        }
        return null;
    }

    private static void updatePassword(String name, String newPassword) throws Exception {
        List<String[]> passwords = readPasswords();
        try (FileWriter fw = new FileWriter(PASSWORDS_FILE, false);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            for (String[] entry : passwords) {
                if (entry[0].equals(name)) {
                    Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
                    cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
                    //uzsifruojamas naujas slaptazodis
                    byte[] encryptedPassword = cipher.doFinal(newPassword.getBytes());
                    entry[1] = Base64.getEncoder().encodeToString(encryptedPassword);
                }
                //Passwordas isvedamas i faila
                out.println(String.join(",", entry));
            }
        }
    }

    private static void deletePassword(String name) throws Exception {
        List<String[]> passwords = readPasswords();
        try (FileWriter fw = new FileWriter(PASSWORDS_FILE, false);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            for (String[] entry : passwords) {
                if (!entry[0].equals(name)) {
                    out.println(String.join(",", entry));
                }
            }
        }
    }
}