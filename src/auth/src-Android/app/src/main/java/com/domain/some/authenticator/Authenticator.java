package com.domain.some.authenticator;

import android.content.SharedPreferences;
import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Authenticator {

    // Err indicators
    public static final int errOK = 0;
    public static final int errNoSuchPadding = 1;
    public static final int errNoSuchAlgorithm = 2;
    public static final int errInvalidKey = 3;
    public static final int errUnsupportedEncoding = 4;
    public static final int errBadPadding = 5;
    public static final int errIllegalBlockSize = 6;
    public static final int errInvalidKeySpec = 7;
    public static final int errInvalidMnemonicSencence = 8;
    public static final int errInvalidPassword = 9;

    // Root hash derivation strategy
    private static final int reduceOpXor = 0;
    private static final int reduceOpConcat = 1;

    private static final String LOG_TAG = MainActivity.class.getSimpleName();
    private static final int reduceOp = reduceOpConcat;
    private static final int seedLen = 16;
    private static final boolean mode_test = false;
    private static final byte[] salt = {41, 86, -69, 14, -6, -78, -98, -44};
    private static final byte[] passwdSalt = {-81, 7, 95, 95, -107, -65, -127, 20};

    private long numOfTokens = 0;
    private int numOfLeaves = 0;
    private int numOfSubLeaves = 0;
    private int chainLen = 0;
    private int treeNum = 0;
    private String seed;
    private int tokenSize = 16;
    private long lastID = -1;
    private byte[] passwdHash;
    private String passwd;

    public static byte[] sha256Digest(byte[] data) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return digest.digest(data);
    }

    public static byte[] sha256DigestSalted(byte[] data, byte[] salt) {
        byte[] dataWithSalt = new byte[data.length + salt.length];
        System.arraycopy(data, 0, dataWithSalt, 0, data.length);
        System.arraycopy(salt, 0, dataWithSalt, data.length, salt.length);

        return sha256Digest(dataWithSalt);
    }

    public static byte[] keccakDigest(byte[] data) {
        Keccak.DigestKeccak kecc = new Keccak.Digest256();
        kecc.update(data);
        return kecc.digest();
    }

    private byte[] performOp(byte[] op1, byte[] op2, int strat) {
        byte[] opArr;

        if (strat == reduceOpConcat) {
            opArr = new byte[op1.length + op2.length];

            System.arraycopy(op1, 0, opArr, 0, op1.length);
            System.arraycopy(op2, 0, opArr, op1.length, op2.length);
        } else if (strat == reduceOpXor) {
            opArr = new byte[op1.length];

            for (int j = 0; j < tokenSize; j++)
                opArr[j] = (byte)(op1[j] ^ op2[j]);
        } else {
            // fallback
            opArr = new byte[op1.length];
        }

        return opArr;
    }

    private void reduceMTLayer(List<byte[]> tokens, int length, int strat) {
        for (int i = 0; i <= (length / 2) - 1; i++) {
            byte[] leftSibling = tokens.get(2 * i);
            byte[] rightSibling = tokens.get(2 * i + 1);
            byte[] opArr;

            opArr = performOp(leftSibling, rightSibling, strat);

            byte[] hash = keccakDigest(opArr);

            tokens.set(i, Arrays.copyOfRange(hash,0, tokenSize));
        }
    }

    private byte[] reduceMT(List<byte[]> tokens, int length, int strat) {
        if (1 == length)
            return tokens.get(0);

        reduceMTLayer(tokens, length, strat);

        return reduceMT(tokens, length / 2, strat);
    }

    private List<byte[]> hashByteArrListAndFuseIDs(List<byte[]> byteArr) {
        List<byte[]> tokens = new ArrayList<>();

        for (int i = 0; i < byteArr.size(); i++) {
            byte[] token = byteArr.get(i).clone();
            byte[] bytesID = Utility.getLeftPaddedIntArray(i, tokenSize, 1);

            for (int j = 0; j < tokenSize; j++)
                token[j] ^= bytesID[j];

            byte[] hash = keccakDigest(token);
            tokens.add(Arrays.copyOfRange(hash,0,tokenSize));
        }

        return tokens;
    }

    private List<byte[]> hashByteArrList(List<byte[]> byteArr) {
        List<byte[]> tokens = new ArrayList<>();

        for (int i = 0; i < byteArr.size(); i++) {
            byte[] token = byteArr.get(i).clone();
            byte[] hash = keccakDigest(token);

            tokens.add(Arrays.copyOfRange(hash,0,tokenSize));
        }

        return tokens;
    }

    private byte[] generateSecretToken(byte[] seed, long id) {
        byte[] bytesID = Utility.longToByteArray(id);
        byte[] byteIDHash = Arrays.copyOfRange(keccakDigest(bytesID), 0, tokenSize);
        byte[] seedNoCheckSum = Arrays.copyOfRange(seed, 0, seed.length - 1);

        byte[] bytesConcat = new byte[seedNoCheckSum.length + byteIDHash.length];
        System.arraycopy(seedNoCheckSum, 0, bytesConcat, 0, seedNoCheckSum.length);
        System.arraycopy(byteIDHash, 0, bytesConcat, seedNoCheckSum.length, byteIDHash.length);

        byte[] token = keccakDigest(bytesConcat);

        return Arrays.copyOfRange(token, 0, tokenSize);
    }

    private byte[] generateTestSecretToken(long idx) {
        long token = 1 + idx * 10;
        return Utility.getLeftPaddedLongArray(token, tokenSize,1);
    }

    private Cipher cipherInit(int cipherMode, SecretKey secretKey, byte[] iv, String cipherAlgorithm) {

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(cipherAlgorithm);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        try {
            if (iv == null) {
                cipher.init(cipherMode, secretKey);
            } else {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(cipherMode, secretKey, ivSpec);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return cipher;
    }

    private Cipher cipherInitPassDict(int cipherMode, String passphrase, List<String> dictionary, String keyAlgorithm, String cipherAlgorithm) {
        byte[] mnemonicSentenceInBytes = Utility.mnemonicSentenceToByteArray(passphrase, dictionary);
        if (mnemonicSentenceInBytes == null)
            return null;
        // Strip checksum
        byte[] secretKeyInBytes = Arrays.copyOfRange(mnemonicSentenceInBytes, 0, mnemonicSentenceInBytes.length - 1);

        // Only first 16B
        byte[] iv = Arrays.copyOfRange(sha256Digest(secretKeyInBytes), 0, 16);

        SecretKey secretKey = new SecretKeySpec(secretKeyInBytes, 0, secretKeyInBytes.length, keyAlgorithm);

        return cipherInit(cipherMode, secretKey, iv, cipherAlgorithm);
    }

    private Cipher cipherInitPass(int cipherMode, String passphrase, String keyAlgorithm, String cipherAlgorithm) {
        final int keyLengthInBits = 256;
        final int keyIterationCount = 4096;

        SecretKeyFactory factory = null;
        Security.addProvider(new BouncyCastleProvider());
        try {
            if (android.os.Build.VERSION.SDK_INT < 27)
                factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC");
            else
                factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BC");
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, keyIterationCount, keyLengthInBits);
        SecretKey tmp;
        try {
            tmp = factory.generateSecret(spec);
            if (tmp == null)
                return null;
        } catch (InvalidKeySpecException e) {
            return null;
        }
        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

        byte[] iv = Arrays.copyOfRange(keccakDigest(passphrase.getBytes()), 0, 16);

        return cipherInit(cipherMode, secretKey, iv, cipherAlgorithm);
    }

    public int initAuthenticator(String _seed, String _password, int _numOfLeaves, int _numOfSubLeafs, int _chainLen) {
        seed = _seed;
        numOfLeaves = _numOfLeaves;
        numOfSubLeaves = _numOfSubLeafs;
        chainLen = _chainLen;
        numOfTokens = (long) numOfLeaves * chainLen;
        passwd = _password;
        passwdHash = sha256DigestSalted(passwd.getBytes(), passwdSalt);

        if (passwdHash == null)
            return  errInvalidPassword;

        treeNum = 0;
        lastID = numOfTokens - 1;

        return errOK;
    }

    public int getTreeNum() {return treeNum; }

    public long getLastID() {
        return lastID;
    }

    public long getNumOfTokens() {
        return numOfTokens;
    }

    public String getSeed() {
        return seed;
    }

    public byte[] getPasswdSalt() {
        return passwdSalt;
    }

    public long getNumOfLeaves() { return numOfLeaves; }

    public long getNumOfSubLeaves() { return numOfSubLeaves; }

    public long getChainLen() { return chainLen; }

    private int[] generateRandomSequence(int length, int bound) {
        int[] rndSequence = new int[length];
        SecureRandom rnd = new SecureRandom();

        for (int i = 0; i < length; i++)
            rndSequence[i] = rnd.nextInt(bound);

        return rndSequence;
    }

    private byte[] generateRandomByteSequence(int length) {
        byte[] rndSequence = new byte[length];
        SecureRandom rnd = new SecureRandom();

        rnd.nextBytes(rndSequence);

        return rndSequence;
    }

    public String generateRandomSeed(List<String> dictionary) {
        byte[] rndSequence = generateRandomByteSequence(seedLen);

        return Utility.getMnemonicSentence(rndSequence, dictionary);
    }

    public byte[] getSecretToken(long tokenID, List<String> dictionary) {

        int numOfSubTokens = numOfSubLeaves * chainLen;

        byte[] secretToken;

        //long alpha = chainLen - (((tokenID % numOfSubTokens) / numOfSubLeaves)) - 1;
        long alpha = chainLen - (((tokenID % numOfSubTokens) / numOfSubLeaves)) - 1;
        long beta = ((tokenID / numOfSubTokens) * (numOfSubTokens / chainLen)) + (tokenID % numOfSubLeaves);

        byte[] seedByte = Utility.mnemonicSentenceToByteArray(seed, dictionary);
        if (seedByte == null)
            return null;

        if (mode_test)
            secretToken = generateTestSecretToken(beta + treeNum * numOfLeaves);
        else
            secretToken = generateSecretToken(seedByte, beta + treeNum * numOfLeaves);

        // TODO: Probably should be elsewhere
        if (reduceOp == reduceOpXor) {
            byte[] bytesID = Utility.getLeftPaddedLongArray(tokenID, tokenSize, 1);

            for (int i = 0; i < tokenSize; i++)
                secretToken[i] ^= bytesID[i];
        }

        byte[] hash;
        for (int i = 0; i < alpha; i++) {
            byte[] idxByte = Utility.longToByteArray(i+1);
            byte[] idxByteRed4B = new byte[4];
            System.arraycopy(idxByte, 4, idxByteRed4B, 0, 4);
            byte[] idxStByte = new byte[idxByteRed4B.length + secretToken.length];
            System.arraycopy(idxByteRed4B, 0, idxStByte, 0, idxByteRed4B.length);
            System.arraycopy(secretToken, 0, idxStByte, idxByteRed4B.length, secretToken.length);
            secretToken = idxStByte;

            hash = keccakDigest(secretToken);
            secretToken = Arrays.copyOfRange(hash,0,tokenSize);
        }

        return secretToken;
    }

    public void setTmpPassword(String _passwd) {
        passwd = _passwd;
    }

    public String getTmpPassword() {
        return passwd;
    }

    public int storeData(SharedPreferences persistentData) {
        SharedPreferences.Editor editor = persistentData.edit();

        Cipher cipher = cipherInitPass(Cipher.ENCRYPT_MODE, passwd, "AES", "AES/CBC/PKCS5Padding");

        byte[] encryptedData = null;
        try {
            encryptedData = cipher.doFinal(seed.getBytes());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        String encryptedDataStr = Utility.ByteArrayToString(encryptedData);
        editor.putString("encrypted_data", encryptedDataStr);

        editor.putInt("token_size", tokenSize);
        editor.putLong("last_ID", lastID);
        editor.putString("passwd_hash", Utility.ByteArrayToString(passwdHash));
        editor.putInt("num_of_leaves", numOfLeaves);
        editor.putInt("num_of_sub_leaves", numOfSubLeaves);
        editor.putInt("chain_len", chainLen);
        editor.putInt("tree_num", treeNum);

        editor.commit();

        return 0;
    }

    public boolean checkIfInitialized() {
        return numOfTokens != 0;
    }

    public void incTreeNum(SharedPreferences persistentData) {
        treeNum++;

        SharedPreferences.Editor editor = persistentData.edit();
        editor.putInt("tree_num", treeNum);
        editor.commit();
    }

    public byte[] checkIfPasswordExists(SharedPreferences persistentData) {
        String passwdHashStr = persistentData.getString("passwd_hash", null);
        if (passwdHashStr == null)
            return null;
        return Utility.StringToByteArray(passwdHashStr);
    }

    public int restoreData(SharedPreferences persistentData) {

        int tokenSizePer = persistentData.getInt("token_size", -1);
        if (tokenSizePer == -1)
            return 1;
        tokenSize = tokenSizePer;

        Cipher cipher = cipherInitPass(Cipher.DECRYPT_MODE, passwd, "AES", "AES/CBC/PKCS5Padding");

        String encryptedDataStr = persistentData.getString("encrypted_data", null);
        if (encryptedDataStr == null)
            return 1;

        byte[] encryptedDatabytes = Utility.StringToByteArray(encryptedDataStr);
        byte[] decrpytedData = null;
        try {
            decrpytedData = cipher.doFinal(encryptedDatabytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        seed = new String(decrpytedData);

        long lastIDPer = persistentData.getLong("last_ID", -1);
        if (lastIDPer == -1)
            return 1;
        lastID = lastIDPer;

        String passwdHashStr = persistentData.getString("passwd_hash", null);
        if (passwdHashStr == null)
            return 1;
        passwdHash = Utility.StringToByteArray(passwdHashStr);

        int numOfLeavesPer = persistentData.getInt("num_of_leaves", -1);
        if (numOfLeavesPer == -1)
            return 1;
        numOfLeaves = numOfLeavesPer;

        int numOfSubLeavesPer = persistentData.getInt("num_of_sub_leaves", -1);
        if (numOfSubLeavesPer == -1)
            return 1;
        numOfSubLeaves = numOfSubLeavesPer;

        int chainLenPer = persistentData.getInt("chain_len", -1);
        if (chainLenPer == -1)
            return 1;
        chainLen = chainLenPer;

        int treeNumPer = persistentData.getInt("tree_num", -1);
        if (treeNumPer == -1)
            return 1;
        treeNum = treeNumPer;

        numOfTokens = (long) numOfLeaves * chainLen;

        return 0;
    }

    public void reset(SharedPreferences persistentData) {
        SharedPreferences.Editor editor = persistentData.edit();

        editor.remove("encrypted_data");
        editor.remove("token_size");
        editor.remove("last_ID");
        editor.remove("passwd_hash");
        editor.remove("num_of_leaves");
        editor.remove("num_of_sub_leaves");
        editor.remove("chain_len");
        editor.remove("tree_num");
        editor.commit();
    }
}
