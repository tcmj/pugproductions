package com.tcmj.common.lang;

import java.io.InputStream;
import java.util.Properties;
import com.tcmj.common.text.HumanReadable;
import org.apache.commons.lang3.StringUtils;

/**
 * Common application tools.
 *
 * @author tcmj - Thomas Deutsch
 * @since 23.01.2011
 */
public class Application {

    private static volatile Application instance;
    final Class<?> context;

    /** private default no-arg-constructor. */
    private Application(final Class<?> context) {
        this.context = context;
    }

    public static Application get(final Class<?> context) {
        Application result = instance;
        if (result == null) { // First check (no locking)
            synchronized (Application.class) {
                result = instance;
                if (result == null) { // Second check (with locking)
                    instance = result = new Application(context);
                }
            }
        }
        return result;
    }

    /**
     * Tries to read the application title provided from the manifests implementation entries. The following order will be used to get the title
     * <ol>
     * <li>Manifest entry 'Implementation-Title'</li>
     * <li>Manifest entry 'Specification-Title'</li>
     * </ol>
     *
     * @param context a class which is located in the same jarfile of the manifest.mf
     * @return the title or an empty string
     * @throws java.lang.IllegalArgumentException if the parameter 'context' is null
     */
    public static String getApplicationTitle(Class<?> context) {
        Objects.notNull(context, "Parameter 'context' may not be null!");
        String title = "";
        String implementationTitle = context.getPackage().getImplementationTitle();
        if (StringUtils.isNotBlank(implementationTitle)) {
            title = implementationTitle;
        } else {
            String specificationTitle = context.getPackage().getSpecificationTitle();
            if (StringUtils.isNotBlank(specificationTitle)) {
                title = specificationTitle;
            }
        }
        return title;
    }

    /**
     * Tries to read the application version provided from the manifests implementation entries. The following order will be used to get it
     * <ol>
     * <li>Manifest entry 'Implementation-Version'</li>
     * <li>Manifest entry 'Specification-Version'</li>
     * </ol>
     * @param context a class which is located in the same jarfile of the manifest.mf
     * @return the version or an empty string
     * @throws java.lang.IllegalArgumentException if the parameter 'context' is null
     */
    public static String getApplicationVersion(Class<?> context) {
        Objects.notNull(context, "Parameter 'context' may not be null!");
        String version = "";
        String implementationVersion = context.getPackage().getImplementationVersion();
        if (StringUtils.isNotBlank(implementationVersion)) {
            version = implementationVersion;
        } else {
            String specificationVersion = context.getPackage().getSpecificationVersion();
            if (StringUtils.isNotBlank(specificationVersion)) {
                version = specificationVersion;
            }
        }
        return version;
    }

    /**
     * Tries to read the application vendor provided from the manifests implementation entries. The following order will be used to get the vendor
     * <ol>
     * <li>Manifest entry 'Implementation-Vendor'</li>
     * <li>Manifest entry 'Specification-Vendor'</li>
     * </ol>
     *
     * @param context a class which is located in the same jarfile of the manifest.mf
     * @return the vendor or an empty string
     * @throws java.lang.IllegalArgumentException if the parameter 'context' is null
     */
    public static String getApplicationVendor(Class<?> context) {
        Objects.notNull(context, "Parameter 'context' may not be null!");
        String title = "";
        String implementationVendor = context.getPackage().getImplementationVendor();
        if (StringUtils.isNotBlank(implementationVendor)) {
            title = implementationVendor;
        } else {
            String specificationVendor = context.getPackage().getSpecificationVendor();
            if (StringUtils.isNotBlank(specificationVendor)) {
                title = specificationVendor;
            }
        }
        return title;
    }

    /**
     * java.vm.vendor + java.vm.name + java.version + os.arch
     * @return 'Oracle Corporation Java HotSpot(TM) 64-Bit Server VM v1.8.0_45 (amd64)'
     */
    public static String getJavaVersionString() {
        return System.getProperty("java.vm.vendor") + //Oracle Corporation
                " " + System.getProperty("java.vm.name") + //Java HotSpot(TM) 64-Bit Server VM
                " " + System.getProperty("java.version") + //1.8.0_25
                " (" + System.getProperty("os.arch") + ")";  //(64bit/amd64)
    }

    /**
     * @return 'Windows 7 (6.1) Service Pack 1'
     */
    public static String getOsNameAndVersion() {
        return System.getProperty("os.name") + " (v"
                + System.getProperty("os.version") + ") " //Windows 7 (6.1)
                + System.getProperty("sun.os.patch.level"); //Service Pack 1
    }

    /**
     * @return 'FileEncoding: UTF-8, Country: DE, Language: de, Timezone: Europe/Berlin'
     */
    public static String getJavaUserInfos() {
        return "FileEncoding: " + System.getProperty("file.encoding") + //UTF-8
                ", Country: " + System.getProperty("user.country") + //DE
                ", Language: " + System.getProperty("user.language") +//de
                ", Timezone: " + System.getProperty("user.timezone");  //Europe/Berlin
    }

    /**
     * JVM maximum memory in a human readable format.
     * @return '910 MB'
     */
    public static String getMaxMemory() {
        return HumanReadable.bytes(Runtime.getRuntime().maxMemory());
    }

    /**
     * Loads the maven version of a maven created jar file.
     * @param context a class which resides inside the jar file (used to define which jar file to use)
     * @param groupId the maven group id which is equal to the first sub folder name of the META-INF/maven directory.
     * @param artifactId the maven artifact id which is equal to the second sub folder name of the META-INF/maven directory.
     * @return the value of the 'version' key (of the Hashtable entry)
     */
    public static String getMavenVersion(Class context, String groupId, String artifactId) {
        try (InputStream stream = context.getResourceAsStream("/META-INF/maven/" + groupId + "/" + artifactId + "/pom.properties")) {
            Properties prop = new Properties();
            prop.load(stream);
            return prop.getProperty("version");
        } catch (Exception e) {
            return null;
        }
    }

    public String getApplicationTitle() {
        return getApplicationTitle(context);
    }

    public String getApplicationVendor() {
        return getApplicationVendor(context);
    }

    public String getApplicationVersion() {
        return getApplicationVersion(context);
    }
}
