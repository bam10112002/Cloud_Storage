package org.example.cryptography.des;

import com.google.common.primitives.Longs;
import lombok.NonNull;
import org.example.cryptography.AlgorithmInterface;
import org.example.cryptography.exceptions.KeyLenException;
import org.example.cryptography.exceptions.XORException;

import java.nio.ByteBuffer;

public class DES implements AlgorithmInterface {
    private final CustomBitSet key;
    private final CustomBitSet[] roundKeys;

    public DES(long key) {
        this.key = normalizeKey(key);
        this.roundKeys = generateRoundKeys(this.key);
    }
    public DES(@NonNull String key) throws KeyLenException {
        if (key.getBytes().length != 8)
            throw new KeyLenException(64, key.getBytes().length*8);

        this.key = normalizeKey(stringToLong(key));
        this.roundKeys = generateRoundKeys(this.key);
    }

    @Override
    public byte[] encrypt(byte[] data) throws XORException {
        int len = 8;
        byte[] data2 = new byte[len];
        for (int i = 0; i < len; i++)
            data2[i] = data[i];

//        int len = (int)Math.ceil(data.length/8.0) * 8;
        ByteBuffer bytes = ByteBuffer.allocate(len);
        bytes.put(data2);
//        if (data.length%8 != 0){
//            for (int i = 0; i < 8 - data.length%8; i++) {
//                bytes.put((byte) 0);
//            }
//        }
        bytes = bytes.position(0);
        ByteBuffer res = ByteBuffer.allocate(len);
//        for (int i = 0; i < len/8; i++) {
//            res.putLong(encrypt(new CustomBitSet(bytes.getLong())).getData());
//        }
        res.putLong(encrypt(new CustomBitSet(bytes.getLong())).getData());
        return res.array();
    }
    @Override
    public byte[] decrypt(byte[] data) throws XORException {
        int len = (int)Math.ceil(data.length/8.0) * 8;
        ByteBuffer bytes = ByteBuffer.allocate(len);
        bytes.put(data);
//        if (data.length%8 != 0){
//            for (int i = 0; i < 8 - data.length%8; i++) {
//                bytes.put((byte) 0);
//            }
//        }
        bytes = bytes.position(0);
        ByteBuffer res = ByteBuffer.allocate(len);
//        for (int i = 0; i < len/8; i++) {
//            res.putLong(decrypt(new CustomBitSet(bytes.getLong())).getData());
//        }
        res.putLong(decrypt(new CustomBitSet(bytes.getLong())).getData());
        return res.array();
    }
    @Override
    public byte[] encrypt(@NonNull ByteBuffer data) throws XORException {
        ByteBuffer res = ByteBuffer.allocate(data.limit());
        for (int i = 0; i < data.limit()/8; i++) {
            res.putLong(encrypt(new CustomBitSet(data.getLong())).getData());
        }
        return res.array();
    }
    @Override
    public byte[] decrypt(@NonNull ByteBuffer data) throws XORException {
        ByteBuffer res = ByteBuffer.allocate(data.limit());
        for (int i = 0; i < data.limit()/8; i++) {
            res.putLong(decrypt(new CustomBitSet(data.getLong())).getData());
        }
        return res.array();
    }

    public @NonNull CustomBitSet decrypt(@NonNull CustomBitSet data) throws XORException {
        data = transformation(data, Matrices.getIp());
        CustomBitSet[] pair = data.split(2);
        CustomBitSet left = pair[0];
        CustomBitSet right = pair[1];
        for (int i = 15; i >= 0; i--) {
            CustomBitSet tmp = new CustomBitSet(left);
            left = right;
            right = tmp.xor(f(right, roundKeys[i]));
        }
        left = left.concat(right);
        return transformation(left, Matrices.getIp_1());
    }

    public @NonNull CustomBitSet encrypt(@NonNull CustomBitSet data) throws XORException {
        data = transformation(data, Matrices.getIp());
        CustomBitSet[] pair = data.split(2);
        CustomBitSet left = pair[0];
        CustomBitSet right = pair[1];
        for (int i = 0; i < 16; i++) {
            CustomBitSet tmp = new CustomBitSet(left);
            left = new CustomBitSet(right);
            right = new CustomBitSet(tmp.xor(f(right, roundKeys[i])));
        }
        left = left.concat(right);
        return transformation(left, Matrices.getIp_1());
    }

    // Служебный функционал
    private @NonNull CustomBitSet normalizeKey(long key) {
        CustomBitSet oldKey = new CustomBitSet(key);
        CustomBitSet newKey = new CustomBitSet();
        newKey.setLen(56);
        for (int i = 0; i < 8; i++) {
            for (int j = 1; j <= 7; j++) {
                newKey.set((i*8+j)-i, oldKey.get(i*8+j));
            }
        }
        return newKey;
    }
    private @NonNull CustomBitSet[] generateRoundKeys(@NonNull CustomBitSet key) {
        key = transformation(key, Matrices.getPc1());
        CustomBitSet[] lrKeys = key.split(2);
        CustomBitSet[] roundKeysMassive = new CustomBitSet[16];

        for (int round = 0; round < 16; round++) {
            lrKeys[0].leftShift(Matrices.getShiftBits()[round]);
            lrKeys[1].leftShift(Matrices.getShiftBits()[round]);
            roundKeysMassive[round] = transformation(lrKeys[0].concat(lrKeys[1]), Matrices.getPc_2());
        }

        return roundKeysMassive;
    }
    private @NonNull CustomBitSet transformation(@NonNull CustomBitSet bitSet, byte[] transformationMatrix) {
        CustomBitSet newBits = new CustomBitSet();
        for (int i = 1; i <= transformationMatrix.length; i++)
            newBits.set(i, bitSet.get(transformationMatrix[i-1]));
        newBits.setLen(transformationMatrix.length);
        return newBits;
    }
    private @NonNull CustomBitSet f(@NonNull CustomBitSet bits, CustomBitSet roundKey) throws XORException {
        bits = transformation(bits, Matrices.getE());
        bits = bits.xor(roundKey);
        CustomBitSet[] sMatrix = bits.split(8);
        CustomBitSet res = new CustomBitSet(0,0);
        for (int i = 0; i < 8; i++) {
            CustomBitSet row = new CustomBitSet(new boolean[] {sMatrix[i].get(5), sMatrix[i].get(0)});
            CustomBitSet column = new CustomBitSet(new boolean[] {sMatrix[i].get(4), sMatrix[i].get(3),
                                                                sMatrix[i].get(2), sMatrix[i].get(1)});
            res = res.concat(new CustomBitSet(Matrices.getS_BOX()[i][(int) row.getData()][(int) column.getData()],4 ));
        }
        return transformation(res, Matrices.getP());
    }
    private long stringToLong(@NonNull String str) {
        long value = 0L;
        for (byte b : str.getBytes())
            value = (value << 8) + (b & 255);
        return value;
    }

    @Override
    public int getBufferSize() {
        return 8;
    }
}
