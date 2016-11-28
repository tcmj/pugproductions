package com.tcmj.common.lang;

import com.google.common.eventbus.EventBus;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

/**
 * Test of com.tcmj.common.lang.Application
 */
public class ApplicationTest {

    /** slf4j Logging framework. */
    private static final transient Logger LOG = LoggerFactory.getLogger(ApplicationTest.class);

    public ApplicationTest() {
        // System.getProperties().entrySet().forEach(entry -> System.out.println("key=" + entry.getKey() + " \t = " + entry.getValue()));
    }

    @Test
    public void testGetApplicationTitle() {
        Class context = getClass();
        String result = Application.get(context).getApplicationTitle();
        LOG.info("getApplicationTitle: '{}'", result);
        assertThat("getApplicationTitle()", result, notNullValue(String.class));
        assertThat("getApplicationTitle(Class)", Application.getApplicationTitle(context), notNullValue(String.class));
    }

    @Test
    public void testGetApplicationVersion() {
        Class context = getClass();
        String result = Application.get(context).getApplicationVersion();
        LOG.info("getApplicationVersion: '{}'", result);
        assertThat("getApplicationVersion()", result, notNullValue(String.class));
        assertThat("getApplicationVersion(Class)", Application.getApplicationVersion(context), notNullValue(String.class));
    }

    @Test
    public void testGetApplicationVendor() {
        Class context = getClass();
        String result = Application.get(context).getApplicationVendor();
        LOG.info("getApplicationVendor: '{}'", result);
        assertThat("getApplicationVendor()", result, notNullValue(String.class));
        assertThat("getApplicationVendor(Class)", Application.getApplicationVendor(Test.class), equalTo("JUnit"));
    }

    @Test
    public void testGetJavaVersionString() {
        String result = Application.getJavaVersionString();
        LOG.info("getJavaVersionString: '{}'", result);
        assertThat("JavaVersionString()", result, notNullValue(String.class));
    }

    @Test
    public void testGetJavaUserInfos() {
        String result = Application.getJavaUserInfos();
        LOG.info("getJavaUserInfos: '{}'", result);
        assertThat("getJavaUserInfos()", result, notNullValue(String.class));
    }

    @Test
    public void testGetOsNameAndVersion() {
        String result = Application.getOsNameAndVersion();
        LOG.info("getOsNameAndVersion:  '{}'", result);
        assertThat("getOsNameAndVersion()", result, notNullValue(String.class));
    }

    @Test
    public void testGetMaxMemory() {
        String result = Application.getMaxMemory();
        LOG.info("getMaxMemory: '{}'", result);
        assertThat("getMaxMemory()", result, notNullValue(String.class));
    }

    @Test
    public void testGetMavenVersion() throws Exception {
        String groupId = "com.google.guava";
        String artifactId = "guava";
        String result = Application.getMavenVersion(EventBus.class, groupId, artifactId);
        LOG.info("getMavenVersion: '{}'", result);
        assertThat("getMavenVersion(Class, String, String)", result, notNullValue(String.class));

        assertThat("getMavenVersion(Class, String, String) - non existant",
                Application.getMavenVersion(EventBus.class, "foo", "bar"), nullValue(String.class));
    }
}
