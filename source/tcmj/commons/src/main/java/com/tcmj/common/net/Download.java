package com.tcmj.common.net;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import com.tcmj.common.lang.Close;
import com.tcmj.common.lang.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Download Helper.<br/>
 * With this class you can download files.
 * @author tcmj - Thomas Deutsch
 * @since 01.05.2012
 */
class Download {


    /** slf4j Logging framework. */
    private static final Logger LOG = LoggerFactory.getLogger(Download.class);

    /** Simultanous server connections/threads. */
    private static final int CONNECTIONS = 8;


    /**
     * instantiation not allowed!
     */
    private Download() {
    }

    /**
     * Downloads a single file from a given url.<br/>
     * This method uses
     * {@link java.nio.channels.FileChannel#transferFrom(java.nio.channels.ReadableByteChannel, long, long)}
     * @param url the url of file which should be downloaded
     * @param target a file handle where you want to save your file. <br/>
     */
    public static void aFile(URL url, File target) throws IOException {
        Objects.notNull(url, "URL parameter may not be null!");
        Objects.notNull(target, "Target file parameter may not be null!");

        InputStream stream = null;
        ReadableByteChannel rbc = null;
        FileOutputStream fos = null;

        try {
            stream = url.openStream();
            rbc = Channels.newChannel(stream);
            fos = new FileOutputStream(target);
            fos.getChannel().transferFrom(rbc, 0, 1 << 24);
        } catch (IOException e) {
            throw e;
        } finally { //cleanup:
            if (fos != null) {
                Close.inSilence(fos.getChannel());
            }
            Close.inSilence(fos);
            Close.inSilence(rbc);
            Close.inSilence(stream);
        }

    }


 public static void aFile2(URL url, File target, int bufferSize) throws IOException {
        Objects.notNull(url, "URL parameter may not be null!");
        Objects.notNull(target, "Target file parameter may not be null!");

     URLConnection urlConnection = url.openConnection();
     LOG.debug("HeaderFields '{}'!", urlConnection.getHeaderFields() );

     long contentLength = urlConnection.getContentLengthLong();
     LOG.debug("Content Length '{}'!", contentLength );

     List<byte[]> chunks = splitChunks(contentLength);
     for(byte[]b : chunks){

     LOG.debug("Chunks '{}'!", b.length );
     }
if(true) return;
     InputStream inputStream = urlConnection.getInputStream();
     try (ReadableByteChannel in = Channels.newChannel(inputStream);
             FileChannel out = new FileOutputStream(target).getChannel()) {

         long transfered = 0;
         long pos = 0;
         do {
             transfered = out.transferFrom(in, pos, bufferSize);
             pos += transfered;
             System.out.println(transfered);
         } while (transfered > 0);

         LOG.debug("Successfully created file '{}'!", target.getAbsolutePath());
     } catch (Exception e) {
            e.printStackTrace();
        }


    }

    /** Splits the downloaded file to n parts. **/
    private static List<byte[]> splitChunks(long contentLength) {

        long end = contentLength % CONNECTIONS;
        if(end == 0){  //try again because we want exactly n connections
            end = contentLength % (CONNECTIONS - 1);
        }
        List<byte[]> chunks = new LinkedList<>();
        long onepart = (contentLength - end) / CONNECTIONS;
        if(onepart > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Download Part is too big!");
        }
        for(int i = 0; i < CONNECTIONS; i++) {
            byte[] part = new byte[(int)onepart];
            chunks.add(part);
        }
        //add the end - but only if there is one
        if(end > 0L){
            chunks.add(new byte[(int)end]);
        }
        //@todo harmonize the chunks that each part has the same size
        byte[] fullpart = chunks.get(0);
        byte[] smallestpart = chunks.get(chunks.size()-1);
        if (smallestpart.length < (fullpart.length / 2)) {
            System.out.println("todo harmonize");
            int diff = fullpart.length - smallestpart.length;
            int rest = diff % chunks.size();
            //...
        }
        return chunks;
    }


    /**
     * Downloads a single file from a given url to the current users temp directory.<br/>
     * This method uses {@link java.nio.channels.FileChannel#transferFrom(java.nio.channels.ReadableByteChannel, long, long)}
     * @param url the url of file which should be downloaded
     * @return a file handle created by
     * {@link File#createTempFile(java.lang.String, java.lang.String)} <br/>
     * additionally uses {@link File#deleteOnExit()} for automatic cleanup
     */
    public static File aFile(URL url) throws IOException {
        File tempfile = File.createTempFile("download", ".tcmj");
        tempfile.deleteOnExit();
        Download.aFile(url, tempfile);
        return tempfile;
    }




    public static void main(String[] args) {
        try {

            System.out.println("Start copy....");

            System.out.println("....End copy!");

            Runnable task1 = new Runnable() {

                @Override
                public void run() {
                    System.out.println(Thread.currentThread().getName() + " is running");
                }
            };

            System.out.println("Start downloading....");




        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    class AsyncDownloadTask implements Future<File> {

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            return false;
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        @Override
        public boolean isDone() {
            return false;
        }

        @Override
        public File get() throws InterruptedException, ExecutionException {
            return null;
        }

        @Override
        public File get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            return null;
        }
    }
//    // Download file.
//    public void run() {
//        RandomAccessFile file = null;
//        InputStream stream = null;
//
//        try {
//            // Open connection to URL.
//            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
//
//            // Specify what portion of file to download.
//            connection.setRequestProperty("Range", "bytes=" + downloaded + "-");
//
//            // Connect to server.
//            connection.connect();
//
//            // Make sure response code is in the 200 range.
//            if (connection.getResponseCode() / 100 != 2) {
//                error();
//            }
//
//            // Check for valid content length.
//            int contentLength = connection.getContentLength();
//            if (contentLength < 1) {
//                error();
//            }
//
//      /*
//       * Set the size for this download if it hasn't been already set.
//       */
//            if (size == -1) {
//                size = contentLength;
//                stateChanged();
//            }
//
//            // Open file and seek to the end of it.
//            file = new RandomAccessFile(getFileName(url), "rw");
//            file.seek(downloaded);
//
//            stream = connection.getInputStream();
//            while (status == DOWNLOADING) {
//        /*
//         * Size buffer according to how much of the file is left to download.
//         */
//                byte buffer[];
//                if (size - downloaded > MAX_BUFFER_SIZE) {
//                    buffer = new byte[MAX_BUFFER_SIZE];
//                } else {
//                    buffer = new byte[size - downloaded];
//                }
//
//                // Read from server into buffer.
//                int read = stream.read(buffer);
//                if (read == -1)
//                    break;
//
//                // Write buffer to file.
//                file.write(buffer, 0, read);
//                downloaded += read;
//                stateChanged();
//            }
//
//      /*
//       * Change status to complete if this point was reached because downloading
//       * has finished.
//       */
//            if (status == DOWNLOADING) {
//                status = COMPLETE;
//                stateChanged();
//            }
//        } catch (Exception e) {
//            error();
//        } finally {
//            // Close file.
//            if (file != null) {
//                try {
//                    file.close();
//                } catch (Exception e) {
//                }
//            }
//
//            // Close connection to server.
//            if (stream != null) {
//                try {
//                    stream.close();
//                } catch (Exception e) {
//                }
//            }
//        }
//    }
//
//    private void stateChanged() {
//        setChanged();
//        notifyObservers();
//    }
//}

}
