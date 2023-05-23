package ru.grimax.blockchain;

import sun.security.provider.DSAPublicKeyImpl;

import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;

public class Transaction {
    private byte[] from;
    private String fromFX;
    private byte[] to;
    private String toFX;
    private Integer value;
    private String timestamp;
    private byte[] signature;
    private String signatureFX;
    private Integer ledgerId;

    public Transaction(byte[] from, byte[] to, Integer value, byte[] signature,
                       Integer ledgerId, String timestamp) {
        Base64.Encoder encoder = Base64.getEncoder();
        this.from = from;
        this.fromFX = encoder.encodeToString(from);
        this.to = to;
        this.toFX = encoder.encodeToString(to);
        this.value = value;
        this.signature = signature;
        this.signatureFX = encoder.encodeToString(signature);
        this.ledgerId = ledgerId;
        this.timestamp = timestamp;
    }

    public Transaction(Wallet fromWalet, byte[] toAddress, Integer value,
                       Integer ledgerId, Signature signing) throws
            InvalidKeyException, SignatureException {
        Base64.Encoder encoder = Base64.getEncoder();
        this.from = fromWalet.getPublicKey().getEncoded();
        this.fromFX = encoder.encodeToString(fromWalet.getPublicKey().getEncoded());
        this.to = toAddress;
        this.toFX = encoder.encodeToString(toAddress);
        this.value = value;
        this.ledgerId = ledgerId;
        this.timestamp = LocalDateTime.now().toString();
        signing.initSign(fromWalet.getPrivateKey());
        String sr = this.toString();
        signing.update(sr.getBytes());
        this.signature = signing.sign();
        this.signatureFX = encoder.encodeToString(this.signature);
    }

    public byte[] getFrom() {
        return from;
    }

    public void setFrom(byte[] from) {
        this.from = from;
    }

    public String getFromFX() {
        return fromFX;
    }

    public void setFromFX(String fromFX) {
        this.fromFX = fromFX;
    }

    public byte[] getTo() {
        return to;
    }

    public void setTo(byte[] to) {
        this.to = to;
    }

    public String getToFX() {
        return toFX;
    }

    public void setToFX(String toFX) {
        this.toFX = toFX;
    }

    public Integer getValue() {
        return value;
    }

    public void setValue(Integer value) {
        this.value = value;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public String getSignatureFX() {
        return signatureFX;
    }

    public void setSignatureFX(String signatureFX) {
        this.signatureFX = signatureFX;
    }

    public Integer getLedgerId() {
        return ledgerId;
    }

    public void setLedgerId(Integer ledgerId) {
        this.ledgerId = ledgerId;
    }

    public Boolean isVerified(Signature signing) throws
            InvalidKeyException, SignatureException {
        signing.initVerify(new DSAPublicKeyImpl(this.getFrom()));
        signing.update(this.toString().getBytes());
        return signing.verify(this.signature);
    }

    @Override
    public String toString() {
        return "Transaction{" +
                "from=" + Arrays.toString(from) +
                ", to=" + Arrays.toString(to) +
                ", value=" + value +
                ", timeStamp= " + timestamp +
                ", ledgerId=" + ledgerId +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Transaction)) return false;
        Transaction that = (Transaction) o;
        return Arrays.equals(getSignature(), that.getSignature());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getSignature());
    }
}
