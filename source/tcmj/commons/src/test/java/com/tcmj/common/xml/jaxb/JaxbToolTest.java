package com.tcmj.common.xml.jaxb;

import javax.xml.bind.JAXBException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Thomas Deutsch <thomas-deutsch(a.t)tcmj.de>
 */
public class JaxbToolTest {

    public JaxbToolTest() {
    }


    @BeforeClass
    public static void setUpClass() throws Exception {
    }


    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }


    @Test
    public void testCreateXml() throws JAXBException {

        XMLRootObject obj = new XMLRootObject();

        obj.setAnyString("examplevalue");


        JaxbTool.createXml(obj);



    }

}
