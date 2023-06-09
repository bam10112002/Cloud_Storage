package org.example.cryptography.twofish;

import lombok.NonNull;
import org.example.cryptography.AlgorithmInterface;
import org.example.cryptography.exceptions.XORException;
import org.example.cryptography.keys.Key;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

public final class TwoFish implements AlgorithmInterface
{

    private final TwoFishSessionKey sessionKey;

    public TwoFish (Key key) throws InvalidKeyException {
        sessionKey = makeSessionKey(((TwoFishKey)key).getKey());
    }

    public static byte[][] P = ConfigTwoFish.P;

    private static final int P_00 = 1;
    private static final int P_01 = 0;
    private static final int P_02 = 0;
    private static final int P_03 = P_01 ^ 1;
    private static final int P_04 = 1;

    private static final int P_10 = 0;
    private static final int P_11 = 0;
    private static final int P_12 = 1;
    private static final int P_13 = P_11 ^ 1;
    private static final int P_14 = 0;

    private static final int P_20 = 1;
    private static final int P_21 = 1;
    private static final int P_22 = 0;
    private static final int P_23 = P_21 ^ 1;
    private static final int P_24 = 0;

    private static final int P_30 = 0;
    private static final int P_31 = 1;
    private static final int P_32 = 1;
    private static final int P_33 = P_31 ^ 1;
    private static final int P_34 = 1;


    private static final int GF256_FDBK_2 = 0x169 / 2;
    private static final int GF256_FDBK_4 = 0x169 / 4;

    private static final int[][] MDS = new int[4][256];

    private static final int RS_GF_FDBK = 0x14D;

    static {
        int[] m1 = new int[2];
        int[] mX = new int[2];
        int[] mY = new int[2];
        int i, j;
        for (i = 0; i < 256; i++) {
            j = P[0][i] & 0xFF;
            m1[0] = j;
            mX[0] = _X( j ) & 0xFF;
            mY[0] = _Y( j ) & 0xFF;

            j = P[1][i]       & 0xFF;
            m1[1] = j;
            mX[1] = _X( j ) & 0xFF;
            mY[1] = _Y( j ) & 0xFF;

            MDS[0][i] = m1[P_00] <<  0 |
                    mX[P_00] <<  8 |
                    mY[P_00] << 16 |
                    mY[P_00] << 24;
            MDS[1][i] = mY[P_10] <<  0 |
                    mY[P_10] <<  8 |
                    mX[P_10] << 16 |
                    m1[P_10] << 24;
            MDS[2][i] = mX[P_20] <<  0 |
                    mY[P_20] <<  8 |
                    m1[P_20] << 16 |
                    mY[P_20] << 24;
            MDS[3][i] = mX[P_30] <<  0 |
                    m1[P_30] <<  8 |
                    mY[P_30] << 16 |
                    mX[P_30] << 24;
        }
    }

    private static int LFSR1( int x ) {
        return (x >> 1) ^ ((x & 0x01) != 0 ? GF256_FDBK_2 : 0);
    }

    private static int LFSR2( int x ) {
        return (x >> 2) ^
                ((x & 0x02) != 0 ? GF256_FDBK_2 : 0) ^
                ((x & 0x01) != 0 ? GF256_FDBK_4 : 0);
    }

    private static int _X(int x ) { return x ^ LFSR2(x); }
    private static int _Y(int x ) { return x ^ LFSR1(x) ^ LFSR2(x); }

    public static TwoFishSessionKey makeSessionKey (byte[] key)
            throws InvalidKeyException {
        if (key == null)
            throw new InvalidKeyException("Key is empty, key must not by null");
        int length = key.length;
        if (!(length == 8 || length == 16 || length == 24 || length == 32))
            throw new InvalidKeyException("Incorrect key length");

        int k64Cnt = length / 8;
        int subkeyCnt = ConfigTwoFish.SUBKEYS + 2*16;
        int[] k32e = new int[4]; // even 32-bit entities
        int[] k32o = new int[4]; // odd 32-bit entities
        int[] sBoxKey = new int[4];
        //
        int i, j, offset = 0;
        for (i = 0, j = k64Cnt-1; i < 4 && offset < length; i++, j--) {
            k32e[i] = (key[offset++] & 0xFF)       |
                    (key[offset++] & 0xFF) <<  8 |
                    (key[offset++] & 0xFF) << 16 |
                    (key[offset++] & 0xFF) << 24;
            k32o[i] = (key[offset++] & 0xFF)       |
                    (key[offset++] & 0xFF) <<  8 |
                    (key[offset++] & 0xFF) << 16 |
                    (key[offset++] & 0xFF) << 24;
            sBoxKey[j] = RS_MDS_Encode( k32e[i], k32o[i] ); // reverse order
        }

        int q, A, B;
        int[] subKeys = new int[subkeyCnt];
        for (i = q = 0; i < subkeyCnt/2; i++, q += 0x02020202) {
            A = F32( k64Cnt, q, k32e );
            B = F32( k64Cnt,q+0x01010101, k32o );
            B = B << 8 | B >>> 24;
            A += B;
            subKeys[2*i    ] = A;
            A += B;
            subKeys[2*i + 1] = A << 9 | A >>> (32-9);
        }

        int k0 = sBoxKey[0];
        int k1 = sBoxKey[1];
        int k2 = sBoxKey[2];
        int k3 = sBoxKey[3];
        int b0, b1, b2, b3;
        int[] sBox = new int[4 * 256];
        for (i = 0; i < 256; i++) {
            b0 = b1 = b2 = b3 = i;
            switch (k64Cnt & 3) {
                case 1:
                    sBox[2*i]         = MDS[0][(P[P_01][b0] & 0xFF) ^ b0(k0)];
                    sBox[2*i+1]       = MDS[1][(P[P_11][b1] & 0xFF) ^ b1(k0)];
                    sBox[0x200+2*i]   = MDS[2][(P[P_21][b2] & 0xFF) ^ b2(k0)];
                    sBox[0x200+2*i+1] = MDS[3][(P[P_31][b3] & 0xFF) ^ b3(k0)];
                    break;
                case 0:
                    b0 = (P[P_04][b0] & 0xFF) ^ b0(k3);
                    b1 = (P[P_14][b1] & 0xFF) ^ b1(k3);
                    b2 = (P[P_24][b2] & 0xFF) ^ b2(k3);
                    b3 = (P[P_34][b3] & 0xFF) ^ b3(k3);
                case 3:
                    b0 = (P[P_03][b0] & 0xFF) ^ b0(k2);
                    b1 = (P[P_13][b1] & 0xFF) ^ b1(k2);
                    b2 = (P[P_23][b2] & 0xFF) ^ b2(k2);
                    b3 = (P[P_33][b3] & 0xFF) ^ b3(k2);
                case 2:
                    sBox[2*i]         = MDS[0][(P[P_01][(P[P_02][b0] & 0xFF) ^ b0(k1)] & 0xFF) ^ b0(k0)];
                    sBox[2*i+1]       = MDS[1][(P[P_11][(P[P_12][b1] & 0xFF) ^ b1(k1)] & 0xFF) ^ b1(k0)];
                    sBox[0x200+2*i]   = MDS[2][(P[P_21][(P[P_22][b2] & 0xFF) ^ b2(k1)] & 0xFF) ^ b2(k0)];
                    sBox[0x200+2*i+1] = MDS[3][(P[P_31][(P[P_32][b3] & 0xFF) ^ b3(k1)] & 0xFF) ^ b3(k0)];
            }
        }
        return new TwoFishSessionKey(sBox, subKeys);
    }

    private static int b0(int x) { return  x & 0xFF; }
    private static int b1(int x) { return (x >>>  8) & 0xFF; }
    private static int b2(int x) { return (x >>> 16) & 0xFF; }
    private static int b3(int x) { return (x >>> 24) & 0xFF; }


    private static int RS_MDS_Encode( int k0, int k1) {
        int r = k1;
        for (int i = 0; i < 4; i++)
            r = RS_rem( r );
        r ^= k0;
        for (int i = 0; i < 4; i++)
            r = RS_rem( r );
        return r;
    }

    private static  int RS_rem( int x ) {
        int b  = (x >>> 24) & 0xFF;
        int g2 = ((b  <<  1) ^ ( (b & 0x80) != 0 ? RS_GF_FDBK : 0 )) & 0xFF;
        int g3 = (b >>>  1)  ^ ( (b & 0x01) != 0 ? (RS_GF_FDBK >>> 1) : 0 ) ^ g2 ;
        return (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
    }

    private static int F32( int k64Cnt, int x, int[] k32 ) {
        int b0 = b0(x);
        int b1 = b1(x);
        int b2 = b2(x);
        int b3 = b3(x);
        int k0 = k32[0];
        int k1 = k32[1];
        int k2 = k32[2];
        int k3 = k32[3];

        int result = 0;
        switch (k64Cnt & 3) {
            case 1:
                result =
                        MDS[0][(P[P_01][b0] & 0xFF) ^ b0(k0)] ^
                                MDS[1][(P[P_11][b1] & 0xFF) ^ b1(k0)] ^
                                MDS[2][(P[P_21][b2] & 0xFF) ^ b2(k0)] ^
                                MDS[3][(P[P_31][b3] & 0xFF) ^ b3(k0)];
                break;
            case 0:
                b0 = (P[P_04][b0] & 0xFF) ^ b0(k3);
                b1 = (P[P_14][b1] & 0xFF) ^ b1(k3);
                b2 = (P[P_24][b2] & 0xFF) ^ b2(k3);
                b3 = (P[P_34][b3] & 0xFF) ^ b3(k3);
            case 3:
                b0 = (P[P_03][b0] & 0xFF) ^ b0(k2);
                b1 = (P[P_13][b1] & 0xFF) ^ b1(k2);
                b2 = (P[P_23][b2] & 0xFF) ^ b2(k2);
                b3 = (P[P_33][b3] & 0xFF) ^ b3(k2);
            case 2:
                result =
                        MDS[0][(P[P_01][(P[P_02][b0] & 0xFF) ^ b0(k1)] & 0xFF) ^ b0(k0)] ^
                                MDS[1][(P[P_11][(P[P_12][b1] & 0xFF) ^ b1(k1)] & 0xFF) ^ b1(k0)] ^
                                MDS[2][(P[P_21][(P[P_22][b2] & 0xFF) ^ b2(k1)] & 0xFF) ^ b2(k0)] ^
                                MDS[3][(P[P_31][(P[P_32][b3] & 0xFF) ^ b3(k1)] & 0xFF) ^ b3(k0)];
                break;
        }
        return result;
    }

    private static int Fe32( int[] sBox, int x, int R ) {
        return sBox[        2*_b(x, R  )    ] ^
                sBox[        2*_b(x, R+1) + 1] ^
                sBox[0x200 + 2*_b(x, R+2)    ] ^
                sBox[0x200 + 2*_b(x, R+3) + 1];
    }

    private static int _b( int x, int N) {
        int result = 0;
        switch (N%4) {
            case 0: result = b0(x); break;
            case 1: result = b1(x); break;
            case 2: result = b2(x); break;
            case 3: result = b3(x); break;
        }
        return result;
    }

    @Override
    public byte[] encrypt(byte[] data) {
        int inOffset = 0;
        int[] sBox = sessionKey.getsBox();
        int[] sKey = sessionKey.getsKey();

        int x0 = (data[inOffset++] & 0xFF)       |
                (data[inOffset++] & 0xFF) <<  8 |
                (data[inOffset++] & 0xFF) << 16 |
                (data[inOffset++] & 0xFF) << 24;
        int x1 = (data[inOffset++] & 0xFF)       |
                (data[inOffset++] & 0xFF) <<  8 |
                (data[inOffset++] & 0xFF) << 16 |
                (data[inOffset++] & 0xFF) << 24;
        int x2 = (data[inOffset++] & 0xFF)       |
                (data[inOffset++] & 0xFF) <<  8 |
                (data[inOffset++] & 0xFF) << 16 |
                (data[inOffset++] & 0xFF) << 24;
        int x3 = (data[inOffset++] & 0xFF)       |
                (data[inOffset++] & 0xFF) <<  8 |
                (data[inOffset++] & 0xFF) << 16 |
                (data[inOffset++] & 0xFF) << 24;

        x0 ^= sKey[ConfigTwoFish.I_WHITEN];
        x1 ^= sKey[ConfigTwoFish.I_WHITEN + 1];
        x2 ^= sKey[ConfigTwoFish.I_WHITEN + 2];
        x3 ^= sKey[ConfigTwoFish.I_WHITEN + 3];


        int t0, t1;
        int k = ConfigTwoFish.SUBKEYS;
        for (int R = 0; R < 16; R += 2) {
            t0 = Fe32( sBox, x0, 0 );
            t1 = Fe32( sBox, x1, 3 );
            x2 ^= t0 + t1 + sKey[k++];
            x2  = x2 >>> 1 | x2 << 31;
            x3  = x3 << 1 | x3 >>> 31;
            x3 ^= t0 + 2*t1 + sKey[k++];


            t0 = Fe32( sBox, x2, 0 );
            t1 = Fe32( sBox, x3, 3 );
            x0 ^= t0 + t1 + sKey[k++];
            x0  = x0 >>> 1 | x0 << 31;
            x1  = x1 << 1 | x1 >>> 31;
            x1 ^= t0 + 2*t1 + sKey[k++];

        }
        x2 ^= sKey[ConfigTwoFish.O_WHITEN];
        x3 ^= sKey[ConfigTwoFish.O_WHITEN + 1];
        x0 ^= sKey[ConfigTwoFish.O_WHITEN + 2];
        x1 ^= sKey[ConfigTwoFish.O_WHITEN + 3];


        return new byte[] {
                (byte) x2, (byte)(x2 >>> 8), (byte)(x2 >>> 16), (byte)(x2 >>> 24),
                (byte) x3, (byte)(x3 >>> 8), (byte)(x3 >>> 16), (byte)(x3 >>> 24),
                (byte) x0, (byte)(x0 >>> 8), (byte)(x0 >>> 16), (byte)(x0 >>> 24),
                (byte) x1, (byte)(x1 >>> 8), (byte)(x1 >>> 16), (byte)(x1 >>> 24),
        };
    }

    @Override
    public byte[] encrypt(@NonNull ByteBuffer data) throws XORException {
        return encrypt(data.array());
    }

    @Override
    public byte[] decrypt(@NonNull ByteBuffer data) throws XORException {
        return decrypt(data.array());
    }

    @Override
    public int getBufferSize() {
        return 16;
    }

    @Override
    public byte[] decrypt(byte[] data) {
        int inOffset = 0;
        int[] sBox = sessionKey.getsBox();
        int[] sKey = sessionKey.getsKey();

        int x2 = (data[inOffset++] & 0xFF)       |
                (data[inOffset++] & 0xFF) <<  8 |
                (data[inOffset++] & 0xFF) << 16 |
                (data[inOffset++] & 0xFF) << 24;
        int x3 = (data[inOffset++] & 0xFF)       |
                (data[inOffset++] & 0xFF) <<  8 |
                (data[inOffset++] & 0xFF) << 16 |
                (data[inOffset++] & 0xFF) << 24;
        int x0 = (data[inOffset++] & 0xFF)       |
                (data[inOffset++] & 0xFF) <<  8 |
                (data[inOffset++] & 0xFF) << 16 |
                (data[inOffset++] & 0xFF) << 24;
        int x1 = (data[inOffset++] & 0xFF)       |
                (data[inOffset++] & 0xFF) <<  8 |
                (data[inOffset++] & 0xFF) << 16 |
                (data[inOffset++] & 0xFF) << 24;

        x2 ^= sKey[ConfigTwoFish.O_WHITEN];
        x3 ^= sKey[ConfigTwoFish.O_WHITEN + 1];
        x0 ^= sKey[ConfigTwoFish.O_WHITEN + 2];
        x1 ^= sKey[ConfigTwoFish.O_WHITEN + 3];

        int k = ConfigTwoFish.SUBKEYS + 2*16 - 1;
        int t0, t1;
        for (int R = 0; R < 16; R += 2) {
            t0 = Fe32( sBox, x2, 0 );
            t1 = Fe32( sBox, x3, 3 );
            x1 ^= t0 + 2*t1 + sKey[k--];
            x1  = x1 >>> 1 | x1 << 31;
            x0  = x0 << 1 | x0 >>> 31;
            x0 ^= t0 + t1 + sKey[k--];

            t0 = Fe32( sBox, x0, 0 );
            t1 = Fe32( sBox, x1, 3 );
            x3 ^= t0 + 2*t1 + sKey[k--];
            x3  = x3 >>> 1 | x3 << 31;
            x2  = x2 << 1 | x2 >>> 31;
            x2 ^= t0 + t1 + sKey[k--];
        }
        x0 ^= sKey[ConfigTwoFish.I_WHITEN];
        x1 ^= sKey[ConfigTwoFish.I_WHITEN + 1];
        x2 ^= sKey[ConfigTwoFish.I_WHITEN + 2];
        x3 ^= sKey[ConfigTwoFish.I_WHITEN + 3];

        return new byte[] {
                (byte) x0, (byte)(x0 >>> 8), (byte)(x0 >>> 16), (byte)(x0 >>> 24),
                (byte) x1, (byte)(x1 >>> 8), (byte)(x1 >>> 16), (byte)(x1 >>> 24),
                (byte) x2, (byte)(x2 >>> 8), (byte)(x2 >>> 16), (byte)(x2 >>> 24),
                (byte) x3, (byte)(x3 >>> 8), (byte)(x3 >>> 16), (byte)(x3 >>> 24),
        };
    }

}
