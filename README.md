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

## crypto
