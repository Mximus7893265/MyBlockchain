package ru.grimax.blockchain;

import sun.security.provider.DSAPublicKeyImpl;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;

public class Block implements Serializable {
    private byte[] prevHash;
    private byte[] currHash;
    private String timeStamp;
    private byte[] minedBy;
    private Integer ledgerId = 1;
    private Integer miningPoints = 0;
    private Double luck = 0.0;
    private ArrayList<Transaction> transactionLedger = new ArrayList<Transaction>();

    public Block(byte[] prevHash, byte[] currHash, String timeStamp, byte[] minedBy,Integer ledgerId,
                 Integer miningPoints, Double luck, ArrayList<Transaction> transactionLedger) {
        this.prevHash = prevHash;
        this.currHash = currHash;
        this.timeStamp = timeStamp;
        this.minedBy = minedBy;
        this.ledgerId = ledgerId;
        this.transactionLedger = transactionLedger;
        this.miningPoints = miningPoints;
        this.luck = luck;
    }

    public Block(LinkedList<Block> currentBlockChain) {
        Block lastBlock = currentBlockChain.getLast();
        prevHash = lastBlock.getCurrHash();
        ledgerId = lastBlock.getLedgerId() + 1;
        luck = Math.random() * 1_000_000;
    }

    public Block() {
        prevHash = new byte[]{0};
    }

    public byte[] getPrevHash() {
        return prevHash;
    }

    public void setPrevHash(byte[] prevHash) {
        this.prevHash = prevHash;
    }

    public byte[] getCurrHash() {
        return currHash;
    }

    public void setCurrHash(byte[] currHash) {
        this.currHash = currHash;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }

    public byte[] getMinedBy() {
        return minedBy;
    }

    public void setMinedBy(byte[] minedBy) {
        this.minedBy = minedBy;
    }

    public Integer getLedgerId() {
        return ledgerId;
    }

    public void setLedgerId(Integer ledgerId) {
        this.ledgerId = ledgerId;
    }

    public Integer getMiningPoints() {
        return miningPoints;
    }

    public void setMiningPoints(Integer miningPoints) {
        this.miningPoints = miningPoints;
    }

    public Double getLuck() {
        return luck;
    }

    public void setLuck(Double luck) {
        this.luck = luck;
    }

    public ArrayList<Transaction> getTransactionLedger() {
        return transactionLedger;
    }

    public void setTransactionLedger(ArrayList<Transaction> transactionLedger) {
        this.transactionLedger = transactionLedger;
    }

    public Boolean isVerified(Signature signing) throws InvalidKeyException, SignatureException {
        signing.initVerify(new DSAPublicKeyImpl(this.minedBy));
        signing.update(this.toString().getBytes());
        return signing.verify(this.currHash);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof Block)) return false;
        Block block = (Block) obj;
        return Arrays.equals(getPrevHash(), block.getPrevHash());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getPrevHash());
    }

    @Override
    public String toString() {
        return "Block{" +
                "prevHash="+Arrays.toString(prevHash) +
                ", timeStamp='" + timeStamp + '\'' +
                ", minedBy=" + Arrays.toString(minedBy) +
                ", ledgerId=" + ledgerId +
                ", miningPoints=" + miningPoints +
                ", luck=" + luck +
                '}';
    }
}
