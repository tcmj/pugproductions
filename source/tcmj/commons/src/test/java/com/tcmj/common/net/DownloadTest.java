package com.tcmj.common.net;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import org.apache.commons.lang3.time.StopWatch;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

/**
 *
 * @author tcmj
 */
public class DownloadTest {

    /**
     * internal assertion method used by the tests
     */
    private static final void checkFile(File file) {
        assertThat("filehandle is null", file, notNullValue());
        assertThat("file does not exist", file.exists(), is(true));
        assertThat("filehandle doesn't point to a file", file.isFile(), is(true));
        assertThat("file size zero", file.length(), not(is(0L)));
        System.out.println("Downloaded File: " + file);
        System.out.println("Size: " + file.length() + " bytes");
    }

    //@Test todo fix
    public final void shouldDownloadAFileFromAnUrlToASpecificLocation() throws MalformedURLException, IOException {
        System.out.println("shouldDownloadAFileFromAnUrlToASpecificLocation");

        URL url = new URL("http://tcmj.googlecode.com/files/oisafetool.jar");

        File myfile = new File(System.getProperty("user.dir"), "myjarfile.jar");

        Download.aFile(url, myfile);

        checkFile(myfile);

        try { //to cleanup
            myfile.delete();
        } catch (Exception e) {
        }

    }

    //@Test  todo fix
    public final void shouldDownloadAFileFromAnUrlToASpecificLocation2() throws MalformedURLException, IOException {
        System.out.println("shouldDownloadAFileFromAnUrlToASpecificLocation");
        StopWatch watch = new StopWatch();
//        URL url = new URL("http://tcmj.googlecode.com/files/oisafetool.jar");
        //URL url = new URL("file:///d:/VC_RED.cab");
        URL url = new URL("http://edmundkirwan.com/pub/spoiklin.jar");

        File myfile = new File(System.getProperty("user.dir"), "spoiklin.jar");
        watch.start();
        Download.aFile2(url, myfile,1024);
        watch.stop();
        System.out.println("Time: "+ watch.toString());
        checkFile(myfile);

        try { //to cleanup
            //myfile.delete();
        } catch (Exception e) {
        }

    }

    // @Test todo fix
    public final void shouldDownloadAFileFromAnUrlAsTempFile() throws MalformedURLException, IOException {
        System.out.println("shouldDownloadAFileFromAnUrlAsTempFile");
        URL url = new URL("http://tcmj.googlecode.com/files/oisafetool.jar");
        File downloadedFile = Download.aFile(url);   //file name w
        checkFile(downloadedFile);
    }

    // @Test todo fix
    public final void shouldDownloadAFileFromAnUrlWithParameters() throws MalformedURLException, IOException {
        System.out.println("shouldDownloadAFileFromAnUrlWithParameters");
        URL url = new URL("http://tcmj.googlecode.com/files/oisafetool.jar?user=max&name=mutzke");
        File downloadedFile = Download.aFile(url);   //file name w
        checkFile(downloadedFile);
    }

    // @Test todo fix
    public final void shouldDownloadAHtmlFileFromAnUrlWithParameters() throws MalformedURLException, IOException {
        System.out.println("shouldDownloadAFileFromAnUrlWithParameters");
        URL url = new URL("http://www.theserverside.com/discussions/thread.tss?thread_id=32379");
        File downloadedFile = Download.aFile(url);   //file name w
        checkFile(downloadedFile);
    }
}
