# pugproductions
Professional Open Source Java Project Management Library

## commons
### collections - ResourceBundleMerger
Tool/Class to merge `.properties` Files
```java
ResourceBundleMerger rbm = new ResourceBundleMerger.Builder().input(new String[]{"fileOne", "fileTwo"}).build();
rbm.getOutputFileName();
```
### date - DateTool
Extended functions to work with dates
```java
Date dateS = DateTool.date(2010, 1, 1, 0, 0, 2);
Date dateE = DateTool.date(2010, 1, 5, 3, 45, 22);
Iterator<Date> dayIterator = DateTool.iterate(dateS, dateE);
Date day1 = dayIterator.next();
```
### date - Range
tools to work with date ranges. Calculate overlapping and so on.
```java
Range<Integer> rightOpenRange = new Range<Integer>(0, null);
boolean isTrue = rightOpenRange.overlaps(new Range<Integer>(2, 3));
```
### io - FileTool
Simplify working with files
```java
FileTool.checkIsFileAndExists(FileSystems.getDefault().getPath("DoesNotExist.txt"));
File result = FileTool.locateFile("FileToolTest.class", FileTool.class);
String result = FileTool.read("FileToolTest.class");
```

### lang - Application
Retrieve application specific informations from system properties and manifest from jarfile
```java
String versionFromManifest = Application.get(getClass()).getApplicationVersion();
String osInfo = Application.getOsNameAndVersion();
```

### lang - Close
Swallow checked exceptions and many more
```java
 Close.unchecked(() -> {
   throw new IOException("We choose a checked one!");
 });
```

### lang - ExceptionAdapter
Prints Stacktraces for logging purposes.
```java
 ExceptionAdapter instance = new ExceptionAdapter(new Exception("Checked!"));
 instance.printStackTrace();
```

### lang - Expression
To check for empty things and others.
```java
Expression.isEmpty(list);
Expression.isNotEmpty(list);
```

### lang - Objects
Really nice stuff to check for conditions and throw a custom exception.
```java
Objects.notNull(nullInstance, RuntimeException.class, "Here we have a custom RuntimeException in {}", this);
Objects.nonZero(parameter, "Oh no you cannot use {} as value!", parameter);
Objects.notBlank("   ", "testNotBlank!");
```

### mem - MemoryUtils
Work with all kind of memory informations of the JVM.
```java
double result = new MemoryUtils().getMemoryUsedPercentage();
```

### net - Download
Downloading files in a performant manner.
```java
File downloadedFile = Download.aFile(url);
```

### reflection - ReflectionHelper
Simplify java reflection.
```java
Object newObject = ReflectionHelper.newObject("java.lang.StringBuilder", null, "Hello");
```

### reflection - ReflectionHelper
Simplify java reflection.
```java
Object newObject = ReflectionHelper.newObject("java.lang.StringBuilder", null, "Hello");
IOException exception = ReflectionHelper.newException(IOException.class, "AnyMessageForOurIOException");
ReflectionHelper.setValue(pojo, "setValueA", "Alpha");
```

### text - CamelCase
Build CamelCase Strings.
```java
CamelCase.toGetter("version_id"); //"getVersionId"
CamelCase.toSetter("last_name"); //"setLastName"
CamelCase.toCamelCase("_un_der_score_word"); //"UnDerScoreWord"
```

### text - HumanReadable
Intelligent Formatter. Displays values eg time values in a human readable format, eg. "ms", "sec", "min", "h", "days"
```java
String result = HumanReadable.milliSec(System.currentTimeInMillis());
HumanReadable.bytes(anyByteValue); //"bytes", "KB", "MB", "GB", "TB"
```

### text - RandomStrings
Build random strings and words
```java
RandomStrings instance = new RandomStrings();
instance.nextString(len);
instance.nextStringCapitalized(len);
instance.randomWord(length);
instance.randomWordCapitalized(length);
instance.nextStringLowerCase(len);
```


### xml - dom - XMLTool
```java
```

### xml - jaxb - RandomStrings
JAXB Tool
```java
JaxbTool.createXml(obj);
```

### xml - map - XMLMap
Reads any xml file in a standard java Map. Including methods to save and reload it.
```java
XMLMap xmap = new XMLMap(file);
xmap.setXMLRootNodeName("project");
xmap.setXMLEntryPoint("dependencies");
xmap.readXML();
```


-----


## crypto

### AES
AES implementation which concatenates
```java
        //we want to encrypt following data....we can encrypt anything which can be converted to a byte array
        byte[] data2Encrypt = "This is our secret data which can be any bytes we want to encrypt!".getBytes();
        char[] password = "aG§s5 Srt234!MyP assw0rd!!".toCharArray(); //passwords should be held in character arrays, not String's!

        //we start by creating an AES object...(the empty constructor is defaulting to some initial parameters, eg. 128 bit mode)
        AES encryptor = new AES();
        //first we need a salt... we choose to generate a new random one
        byte[] salt = encryptor.generateSalt();
        //next we create our AES key object using our secret password and the previously created salt
        SecretKey key = encryptor.generateKey(password, salt);

        //apply encryption producing extended cipher data
        byte[] encryptedA = encryptor.encryptAndMerge(key, salt, data2Encrypt);

        //apply decryption
        AES decryptor = new AES(); //(we simulate a separate session and use NOT the same AES object for encryption and decryption)
        byte[] decrypted = decryptor.decryptMergedData(password, encryptedA);
        //we only have to convert our byte array back to String:
        System.out.println("Data: '" + new String(decrypted) + "'");

        //proof:
        assertThat(decrypted, equalTo(data2Encrypt));
```


### Crypto Tool
Hack to emulate Extended Java installation (JCE jurisdiction policy files). So you don't have to install JCE separately!
```java
Crypto.removeCryptographyRestrictions();
```
