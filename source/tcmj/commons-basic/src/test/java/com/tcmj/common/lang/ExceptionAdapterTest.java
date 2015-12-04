package com.tcmj.common.lang;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.text.DecimalFormat;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * ExceptionAdapter Test.
 */
public class ExceptionAdapterTest {

    /**
     * Test of printStackTrace method, of class ExceptionAdapter.
     */
    @Test
    public void testPrintStackTrace() {
        System.out.println("printStackTrace");

        ExceptionAdapter instance = new ExceptionAdapter(new Exception("Checked!"));
        instance.printStackTrace();

    }


    @Test
    public void testByteZeugs() {
        System.out.println("bits and bytes");

        byte one = 0b1111111;
        System.out.println("bit="+one);

        Integer two = 0b01111111_11111111_11111111_11111111 ;
        System.out.println("two="+two);

        BigInteger big = new BigInteger("127");
        System.out.println("big="+big+ " length="+big.toByteArray().length);
        System.out.println("big.setBit(7) = "+big.setBit(7));;
        System.out.println("big.setBit(7) = "+big.setBit(7).bitLength());;
        System.out.println("big.setBit(7) = "+big.setBit(3).byteValueExact());;
        System.out.println("signum = "+big.signum());
        System.out.println("bitcount = "+big.bitCount());
        System.out.println("bitlength = "+big.bitLength());
        BigInteger bi = big.setBit(7);
        for (int i = 0; i < 8; i++) {
        System.out.println("bit-"+i+"="+bi.testBit(i));

        }

        System.out.println("rad-2-"+new BigInteger("1",2));
        System.out.println("rad-2-"+new BigInteger("101",2));

        System.out.println("rad-3-"+new BigInteger("1",3));
        System.out.println("rad-3-"+new BigInteger("1000",3));

        System.out.println("rad-5-"+new BigInteger("1",5));
        System.out.println("rad-5-"+new BigInteger("23",5));

        System.out.println("rad-8-"+new BigInteger("1",8));
        System.out.println("rad-8-"+new BigInteger("10",8));
        System.out.println("rad-8-"+new BigInteger("23",8));

        System.out.println("rad-10-"+new BigInteger("1",20));
        System.out.println("rad-10-"+new BigInteger("10",20));
        System.out.println("rad-10-"+new BigInteger("23",20));

    }





}
