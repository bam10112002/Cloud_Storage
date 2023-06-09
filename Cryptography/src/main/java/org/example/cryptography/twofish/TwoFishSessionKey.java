package org.example.cryptography.twofish;

public class TwoFishSessionKey {
    private final int[] sBox;
    private final int[] sKey;

    public TwoFishSessionKey(int[] sBox, int[] sKey) {
        this.sBox = sBox;
        this.sKey = sKey;
    }

    public int[] getsBox() {
        return sBox;
    }

    public int[] getsKey() {
        return sKey;
    }
}
