package com.domain.some.authenticator;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// QR
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import android.graphics.Bitmap;

public class Utility {

    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();
    private static List<String> dict = null;

    public static void setDict(List<String> dictionary) {
        dict = dictionary;
    }

    public static List<String> getDict() {
        return dict;
    }

    // Method created by maybeWeCouldStealAVan from StackOverflow
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] mnemonicSentenceToByteArray(String passphrase, List<String> dictionary) {
        final int bitsInByte = 8;
        final int mnemonicLenInBits = 11;

        String[] words = passphrase.split(" ");

        if (words.length % 3 != 0)
            return null;

        int mnemonicSentenceLenInBits = words.length * mnemonicLenInBits;
        int[] wordsIndexes = new int[words.length];

        for (int i = 0; i < words.length; i++)
            wordsIndexes[i] = dictionary.indexOf(words[i]);

        BitArray mnemonicSentenceInBits = new BitArray(mnemonicSentenceLenInBits);
        mnemonicSentenceInBits.fillBitArray(wordsIndexes);

        int checkSumBits = mnemonicSentenceLenInBits / 32;
        int mnemonicSentenceByteArrayLen = mnemonicSentenceLenInBits / bitsInByte;
        if (mnemonicSentenceLenInBits % bitsInByte != 0)
            mnemonicSentenceByteArrayLen++;
        byte[] mnemonicSentenceByteArray = new byte[mnemonicSentenceByteArrayLen];

        int k = 0;
        for (int i = 0; i < mnemonicSentenceByteArray.length; i++) {
            byte value = 0;
            for (int j = 0; j < bitsInByte && k < mnemonicSentenceLenInBits; j++,k++) {
                value <<= 1;
                value |= mnemonicSentenceInBits.getBit(k) ? 1 : 0;
            }

            mnemonicSentenceByteArray[i] = value;
        }
        mnemonicSentenceByteArray[mnemonicSentenceByteArray.length - 1] <<= (bitsInByte - checkSumBits);

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] hash = digest.digest(Arrays.copyOfRange(mnemonicSentenceByteArray, 0, mnemonicSentenceByteArray.length - 1));
        if (hash == null)
            return null;

        byte mask = 0;
        for (int i = 0; i < checkSumBits; i++) {
            mask <<= 1;
            mask |= 1;
        }
        mask <<= (bitsInByte - checkSumBits);

        byte hashChecksum = (byte)(hash[0] & mask);
        if (hashChecksum != mnemonicSentenceByteArray[mnemonicSentenceByteArray.length - 1])
            return null;

        return mnemonicSentenceByteArray;
    }

    public static String getMnemonicSentence(byte[] data, List<String> dictionary) {
        final int bitsInByte = 8;
        final int mnemonicLenInBits = 11;

        StringBuffer mnemonicSentence = new StringBuffer("");

        if ((data.length * bitsInByte) % 32 != 0)
            return null;

        int dataLenInBits = data.length * bitsInByte;
        int checkSumBits = (data.length * bitsInByte) / 32;
        int mnemonicSentenceLenInBits = dataLenInBits + checkSumBits;
        int wordsInSentence = mnemonicSentenceLenInBits / mnemonicLenInBits;

        BitArray mnemonicSentenceInBits = new BitArray(mnemonicSentenceLenInBits);
        mnemonicSentenceInBits.fillBitArray(data);

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] hash = digest.digest(data);
        if(hash == null)
            return null;

        for (int i = dataLenInBits, j = 0; i < dataLenInBits + checkSumBits; i++,j++) {
            mnemonicSentenceInBits.setBit(i, ((0x80 & hash[j / bitsInByte]) != 0));
            hash[j / bitsInByte] <<= 1;
        }

        int k = 0;
        for (int i = 0; i < wordsInSentence; i++) {
            int mnemonicIndex = 0;
            for (int j = 0; j < mnemonicLenInBits; j++,k++) {
                mnemonicIndex <<= 1;
                mnemonicIndex |= mnemonicSentenceInBits.getBit(k) ? 1 : 0;
            }

            if (i == 0)
                mnemonicSentence.append(dictionary.get(mnemonicIndex));
            else
                mnemonicSentence.append(" ").append(dictionary.get(mnemonicIndex));
        }

        return mnemonicSentence.toString();
    }

    public static int getTreeHeight(int size) {
        int height = 0;

        while(size > 1) {
            height++;
            size >>= 1;
        }

        return height;
    }

    public static String ByteArrayToString(byte[] bytes) {
        return Arrays.toString(bytes);
    }

    public static String ByteArrayListToString(List<byte[]> data) {
        StringBuffer tokenListString = new StringBuffer("");

        int i = 0;
        tokenListString.append(ByteArrayToString(data.get(i++)));

        for (; i < data.size(); i++)
            tokenListString.append(";").append(ByteArrayToString(data.get(i)));

        return tokenListString.toString();
    }

    public static byte[] StringToByteArray(String str) {
        String[] byteValues = str.substring(1, str.length() - 1).split(",");
        byte[] bytes = new byte[byteValues.length];

        for (int i = 0, len = bytes.length; i < len; i++)
            bytes[i] = Byte.parseByte(byteValues[i].trim());

        return bytes;
    }

    public static List<byte[]> StringToByteArrayList(String str) {
        List<byte[]> tokens = new ArrayList<>();

        String[] tokensStrArr = str.split(";");
        for (String item : tokensStrArr)
            tokens.add(StringToByteArray(item));

        return tokens;
    }

    public static String BooleanArrayToString(boolean[] data) {
        return Arrays.toString(data);
    }

    public static boolean[] StringToBooleanArray(String str) {
        String[] boolValues = str.substring(1, str.length() - 1).split(",");
        boolean[] booleans = new boolean[boolValues.length];

        for (int i = 0, len = booleans.length; i < len; i++)
            booleans[i] = Boolean.parseBoolean(boolValues[i].trim());

        return booleans;
    }

    public static List<byte[]> cloneByteArrList(List<byte[]> list) {
        List<byte[]> clone = new ArrayList<>();

        for (int i = 0; i < list.size(); i++)
            clone.add(list.get(i).clone());

        return clone;
    }

    public static int padLeft(byte[] src, int srcSize, byte[] dst, int dstSize) {
        int srcLastIndex = srcSize - 1;
        int dstLastIndex = dstSize - 1;

        if (srcSize > dstSize)
            return 0;

        for (int i = srcLastIndex, j = dstLastIndex; i >= 0; i--,j--)
            dst[j] = src[i];

        return srcSize;
    }

    public static byte[] getLeftPaddedIntArray(int number, int arrSize, int padSt) {
        byte[] byteArrNum = ByteBuffer.allocate(4).putInt(number).array();
        byte[] bytesPadded = new byte[arrSize];

        // TODO: Be aware that we assume 32bit value, but the number is deliver in 64 bit data type
        if (padSt == 0) {
            bytesPadded[0] = byteArrNum[3];
            bytesPadded[1] = byteArrNum[2];
            bytesPadded[2] = byteArrNum[1];
            bytesPadded[3] = byteArrNum[0];
        } else {
            padLeft(byteArrNum, byteArrNum.length, bytesPadded, bytesPadded.length);
        }

        return bytesPadded;
    }

    public static byte[] getLeftPaddedLongArray(long number, int arrSize, int padSt) {
        byte[] byteArrNum = ByteBuffer.allocate(8).putLong(number).array();
        byte[] bytesPadded = new byte[arrSize];

        // TODO: Be aware that we assume 32bit value, but the number is deliver in 64 bit data type
        if (padSt == 0) {
            bytesPadded[0] = byteArrNum[7];
            bytesPadded[1] = byteArrNum[6];
            bytesPadded[2] = byteArrNum[5];
            bytesPadded[3] = byteArrNum[4];
            bytesPadded[4] = byteArrNum[3];
            bytesPadded[5] = byteArrNum[2];
            bytesPadded[6] = byteArrNum[1];
            bytesPadded[7] = byteArrNum[0];
        } else {
            padLeft(byteArrNum, byteArrNum.length, bytesPadded, bytesPadded.length);
        }

        return bytesPadded;
    }

    public static byte[] intToByteArray ( final int i ) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        try {
            dos.writeInt(i);
            dos.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bos.toByteArray();
    }

    public static byte[] longToByteArray ( final long i ) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        try {
            dos.writeLong(i);
            dos.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return bos.toByteArray();
    }

    public static Bitmap encodeAsBitmap(String str) throws WriterException {
        BitMatrix result;
        int WHITE = 0xFFFFFFFF;
        int BLACK = 0xFF000000;
        int WIDTH = 400;
        int HEIGHT = 400;

        try {
            result = new MultiFormatWriter().encode(str, BarcodeFormat.QR_CODE, WIDTH, HEIGHT, null);
        } catch (IllegalArgumentException iae) {
            // Unsupported format
            return null;
        }

        int width = result.getWidth();
        int height = result.getHeight();
        int[] pixels = new int[width * height];
        for (int y = 0; y < height; y++) {
            int offset = y * width;
            for (int x = 0; x < width; x++) {
                pixels[offset + x] = result.get(x, y) ? BLACK : WHITE;
            }
        }

        Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        bitmap.setPixels(pixels, 0, width, 0, 0, width, height);
        return bitmap;
    }

}
