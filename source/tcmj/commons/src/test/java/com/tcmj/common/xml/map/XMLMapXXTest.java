/*
 * XMLMapTest.java
 * JUnit based test
 *
 * Created on 19. April 2007, 23:27
 */
package com.tcmj.common.xml.map;

import java.io.File;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JUnit Test for class {@link XMLMap}
 * @author tcmj
 */
public class XMLMapXXTest {

    private static final transient Logger LOG = LoggerFactory.getLogger(XMLMap.class);

    static {
        System.setProperty("jaxp.debug", "1");
    }


    @Before
    public void beforeEachTest() {
        LOG.info(StringUtils.repeat('-',120));
    }


    // @Test
    public void testXMLEntrypointReading() throws Exception {
        LOG.info("testXMLEntrypoint");
        File testdatapath = new File("D:\\development\\MANTURBO\\MANT_PESAPDCC_V10\\com.inteco.man.turbo\\man-turbo-document-released_service\\conf\\loggingService.xml");
        XMLMap xmap = new XMLMap(testdatapath);


        //1. No Entrypoint
        xmap.readXML();
        LOG.info(xmap.showDataEntries(false, true));
        LOG.info(xmap.getXMLEntryPoint());

        //String layoutcls = xmap.getAttribute("appender.layout", "class");
        //System.out.println("layoutcls = " + layoutcls);


//        xmap.setXMLEntryPoint("one.two.three");
//        xmap.readXML();
//        assertEquals("4", "4711", xmap.get("four.five"));


//        //Create Test-XML-File:
        File out = new File("D:\\xmlmaptest", "XMLMapTestXX_TMP.xml");
        if (out.exists()) {
            out.delete();
        }

        xmap.setXMLFileHandle(out);
        xmap.saveXML();
    }

}
