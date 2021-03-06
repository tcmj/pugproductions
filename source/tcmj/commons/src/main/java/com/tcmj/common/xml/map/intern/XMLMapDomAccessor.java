package com.tcmj.common.xml.map.intern;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.ErrorListener;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Comment;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * XMLMapAccessor implementation
 * @author tcmj
 */
public class XMLMapDomAccessor implements XMLMapAccessor {

    /** slf4j Logging framework. */
    private static final transient Logger LOG = LoggerFactory.getLogger(XMLMapDomAccessor.class);

    /** JAXP XML Document. */
    private transient Document document = null;

    private Map<String, XMLEntry> data;
    private File xmlFile;

    private String xmlEntryPoint;
    private String xmlRootNodeName;
    private String levelSeparator;
    /**
     * compiled pattern to split the keys.
     */
    private Pattern regexpattern;

    public XMLMapDomAccessor(String xmlRootNodeName, String xmlEntryPoint, String levelSeparator, Pattern regexpattern) {
        this.xmlRootNodeName = xmlRootNodeName;
        this.xmlEntryPoint = xmlEntryPoint;
        this.levelSeparator = levelSeparator;
        this.regexpattern = regexpattern;
    }

    /**
     * Internal Method to search for a specific xml node.
     * @param name node name to search for
     * @param parent parent to search under
     * @return the node
     */
    private static Node searchNode(String name, Node parent) {
        Node actnode = parent.getFirstChild();
        while ((actnode != null) && (!name.equals(actnode.getNodeName()))) {
            if (name.equals(actnode.getNodeName())) {
                return actnode;
            } else {
                actnode = actnode.getNextSibling();
            }
        }
        return actnode;
    }

    @Override
    public Map<String, XMLEntry> read(File xmlFile) throws XMLMapException {

        data = new LinkedHashMap<>();

        if (xmlFile.exists()) {
            LOG.debug("Start reading XML-File: {}", xmlFile);

            Element root = null;

            try {

                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

                /* Set namespaceAware to true to get a DOM Level 2 tree with nodes
                 containing namesapce information.  This is necessary because the
                 default value from JAXP 1.0 was defined to be false. */
                factory.setNamespaceAware(true);

                DocumentBuilder builder = factory.newDocumentBuilder();

                //TODO make global - do not read before save!!!
                document = builder.parse(xmlFile);

                root = document.getDocumentElement();

            } catch (ParserConfigurationException | SAXException | IOException ex) {
                LOG.error("Error reading XML: " + ex.getMessage(), ex);
            }

            //Nur wenn es ein Wurzelelement gibt weiterlesen:
            if (root != null) {

                //Falls ein EntryPoint gesetzt wurde, muss dieser
                //gesucht werden und von dort an begonnen werden:
                Node startNode;
                if (getXMLEntryPoint() == null) {
                    startNode = root.getFirstChild();
                } else {
                    try {
                        LOG.debug("Searching for a entry point...");
                        startNode = searchNode(getXMLEntryPoint(), xmlFile.getPath());
                        //nimm den ersten knoten unter dem entrypoint
                        startNode = startNode.getFirstChild();
                    } catch (XPathExpressionException xex) {
                        startNode = null;
                        LOG.error("XPath error: " + xex.getMessage(), xex);
                    } catch (NullPointerException nex) {
                        startNode = null;
                        LOG.error("XMLEntryPoint not found!", nex);
                    }
                }

                //lese vom start-node beginend...
                for (Node uppernode = startNode; uppernode != null; uppernode = uppernode.getNextSibling()) {

                    if (uppernode.getNodeType() == Node.ELEMENT_NODE) {
                        //wenn es sich um ein Element handelt (kein Kommentar..)
                        LOG.debug("Current node: LocalName={} NodeName={} Prefix={}", new Object[]{uppernode.getLocalName(), uppernode.getNodeName(), uppernode.getPrefix()});

                        String nodename = uppernode.getNodeName();
                        deeper(uppernode, nodename);

                    }

                }
            }
        }

        return data;
    }

    /**
     * searches a xml node via xpath.
     *
     * @param nodename nodepath separated with the current path separator
     * @todo candidate for a jaxp helper class.
     */
    private Node searchNode(String nodename, String xmlFilePath) throws XPathExpressionException {

        // 1. Instantiate an XPathFactory.
        javax.xml.xpath.XPathFactory factory = javax.xml.xpath.XPathFactory.newInstance();

        // 2. Use the XPathFactory to create a new XPath object
        javax.xml.xpath.XPath xpath = factory.newXPath();

        //Namespace-prefix-workaround
        if (getXMLRootNodeName().contains(":")) {
            String[] splits = getXMLRootNodeName().split(":");
            //take the first prefix
            final String prfix = splits[0];
            LOG.debug("prefix: {}", prfix);
            //search uri to the prefix
            final String uri = document.lookupNamespaceURI(prfix);
            LOG.debug("uri: {}", uri);
            NamespaceContext nsc = new NamespaceContext() {

                @Override
                public String getNamespaceURI(String prefix) {
                    return uri;
                }

                @Override
                public String getPrefix(String namespaceURI) {
                    return prfix;
                }

                @Override
                public Iterator<?> getPrefixes(String namespaceURI) {
                    throw new UnsupportedOperationException("Not supported yet.");
                }
            };
            xpath.setNamespaceContext(nsc);

//            namespaces.put(prfix, uri);
        }

        //2.1 create xpath expression:
        //TODO create function to split
        String xpathExp = "//".concat(getXMLRootNodeName()).concat("/");
        String[] keyparts = getRegexPattern().split(nodename);
        for (int i = 0; i < keyparts.length; i++) {
            if (i > 0) {
                xpathExp = xpathExp.concat("/");
            }
            xpathExp = xpathExp.concat(keyparts[i]);
        }

        LOG.debug("searching xpath: {}", xpathExp);

        // 3. Compile an XPath string into an XPathExpression
        javax.xml.xpath.XPathExpression expression = xpath.compile(xpathExp);

//        String xmlFilePath = getXMLFile().getPath();
        // 4. Evaluate the XPath expression on an input document
        Node result = (Node) expression.evaluate(new org.xml.sax.InputSource(xmlFilePath), XPathConstants.NODE);

        LOG.debug("xpath-result = {}", result);

        return result;

    }

    /**
     * Iterates recursive throug the XML Nodes.
     * @param node Parent Node
     */
    private void deeper(Node node, String path) {

        Node child = node.getFirstChild();

        if (child != null) {

            String childNodeValue = child.getNodeValue();

            if (childNodeValue != null && !"".equals(childNodeValue.trim())) {

                XMLEntry entry = data.get(path);

                if (entry == null) {
                    LOG.trace("creating a new map entry with key '{}' and value '{}'",  path, childNodeValue);
                    entry = new XMLEntry(path, childNodeValue);
                    this.data.put(path, entry);

                    //search for comments:
                    entry.setComment(searchBackwardForComment(child));

                } else {
                    entry.addValue(childNodeValue);
                }

                parseAttributes(node, entry);

            } else {

                LOG.trace("loading next xml node underneath '{}'...", path);

                while (child != null) {

                    if (child.getNodeType() == Node.ELEMENT_NODE) {

                        String extendedpath = path.concat(levelSeparator).concat(child.getNodeName());

                        deeper(child, extendedpath);
                    } else if (child.getNodeType() == Node.CDATA_SECTION_NODE) {
                        LOG.trace("CDATA_SECTION_NODE = {}", child.getNodeValue());
                        XMLEntry entry = data.get(path);

                        if (entry == null) {
                            LOG.trace("creating a new map entry with key '{}' and value '{}'",  path, child.getNodeValue());
                            entry = new XMLEntry(path, child.getNodeValue());
                            this.data.put(path, entry);
                        } else {
                            entry.addValue(child.getNodeValue());
                        }
                        entry.setXmlNodeType(child.getNodeType());
                    }

                    child = child.getNextSibling();
                }
            }
        } else {
            LOG.trace("no more childs: '{}'", path);
            XMLEntry entry = new XMLEntry(path, node.getNodeValue());
            parseAttributes(node, entry);
            this.data.put(path, entry);
        }
    }

    /**
     * Searching backwards for a comment
     * @return the comment
     */
    private String searchBackwardForComment(Node node) {
        String comment = null;
        Node actualNode =  node.getParentNode();
        do {
            if (actualNode != null && actualNode.getNodeType() == Node.COMMENT_NODE) {
                LOG.trace("comment found: {}", actualNode);
                comment = actualNode.getNodeValue();
            }
            actualNode = actualNode.getPreviousSibling();
        } while (comment == null && actualNode != null);
        return comment;
    }

    private void parseAttributes(Node node, XMLEntry entry) {
        if (node.hasAttributes()) {
            NamedNodeMap nnm = node.getAttributes();
            for (int index = 0; index < nnm.getLength(); index++) {
                Node attnode = nnm.item(index);
                LOG.trace("reading attribute of element '{}': '{}' = '{}'", node, attnode.getNodeName(), attnode.getNodeValue());
                entry.addAttribute(attnode.getNodeName(), attnode.getNodeValue());
            }
        }
    }

    @Override
    public void save(Map<String, XMLEntry> data, File outputfile) throws XMLMapException {
        Objects.requireNonNull(outputfile, "Output file handle may not be null!");

        try {
            //ensure existing dirs
            outputfile.getParentFile().mkdirs();


            Element root;

            if (document == null) {

                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                /* Set namespaceAware to true to get a DOM Level 2 tree with nodes
                 containing namesapce information.  This is necessary because the
                 default value from JAXP 1.0 was defined to be false. */
                factory.setNamespaceAware(true);

                DocumentBuilder builder = factory.newDocumentBuilder();

                document = builder.newDocument();

                root = document.createElement(getXMLRootNodeName());

                document.appendChild(root);
            } else {
                root = document.getDocumentElement();
            }

            //Ermittle ob dieser Knoten ein Kind namens <xMLEntryPoint> hat:
            Node uppernode = root.getFirstChild();

            while ((uppernode != null) && (!uppernode.getNodeName().equals(getXMLEntryPoint()))) {
                uppernode = uppernode.getNextSibling();
            }

            if (uppernode != null) { //wenn er ein Kind namens <xMLEntryPoint> hat...
                Node prevnode = uppernode.getPreviousSibling();

                //...delete the previous whitespace
                if (prevnode != null && prevnode.getNodeType() == Node.TEXT_NODE) {
                    root.removeChild(prevnode);
                }
                //...delete the whole xml entry point
                root.removeChild(uppernode);

            }

            if (getXMLEntryPoint() == null) {
                //use root as xml entry point
                uppernode = root;
            } else {
                //create the xml-entry-point element
                uppernode = document.createElement(getXMLEntryPoint());
                root.appendChild(uppernode);
            }

            //Daten durchlaufen...
            Iterator<XMLEntry> itData = data.values().iterator();

            while (itData.hasNext()) {

                XMLEntry xmlentry = itData.next();

                //Variable fuer die unterste Ebene:
                Node actualnode = uppernode, prevnode = null;

                //Key zerteilen:
                String[] keyparts = getRegexPattern().split(xmlentry.getKey());

                String keypart = null;

                //Schleife durch alle parts des keys, wobei nicht vorhandene ebenen
                //angelegt werden und bereits vorhandene übersprungen!
                //Zudem wird immer der aktuelle Knoten (actnode) und der Vorgänger
                //gespeichert (Vorgänger wird benötigt bei Listen-Values)
                for (String part : keyparts) {
                    keypart = part;
                    //Key-Part suchen:
                    Node ngroup = searchNode(keypart, actualnode);
                    //wenn nicht gefunden --> anlegen:
                    if (ngroup == null) {

                        //vor dem anlegen der letzten Ebene muss ggf der Kommentar geschrieben werden:
                        //if a comment is available we have to write it before the last level
                        if(xmlentry.getComment()!=null && part.equals(keyparts[keyparts.length-1])) {
                            Comment comment = document.createComment(xmlentry.getComment());
                            actualnode.appendChild(comment);
                        }

                        ngroup = document.createElement(keypart);
                    }
                    actualnode.appendChild(ngroup);
                    prevnode = actualnode;
                    actualnode = ngroup;
                }

                if (xmlentry.getValue() != null) { //create single value...

                    //create and set all available attributes on the (single) xml element
                    Map<String, String> allattribs = xmlentry.getAttributes();
                    if (allattribs != null) {
                        for (Map.Entry<String, String> aentry : allattribs.entrySet()) {
                            ((Element) actualnode).setAttribute(aentry.getKey(), aentry.getValue());
                        }
                    }

                    //create and append the text node / cdata text node
                    //todo also implement cdata text node for multiple values aka list values
                    if (xmlentry.getXmlNodeType() == Node.CDATA_SECTION_NODE) {
                        actualnode.appendChild(document.createCDATASection(xmlentry.getValue()));
                    } else {
                        actualnode.appendChild(document.createTextNode(xmlentry.getValue()));
                    }
                } else { //..or create list values

                    //Prepare to create attributes
                    Map<String, String> allattribs = xmlentry.getListAttributes();

                    String[] values = xmlentry.getListValue();
                    String val = values == null ? null : values[0];
                    if (values != null) {
                        //Append the value on the allready existing first tag
                        actualnode.appendChild(document.createTextNode(val));
                        //Process first attribute (if any)
                        if (allattribs != null) {
                            Map.Entry<String, String> aentry = allattribs.entrySet().stream().findFirst().orElse(null);
                            if(aentry!=null){
                                String[] attrvalues = aentry.getValue().split("\\|");
                                if (attrvalues[0] != null) {
                                    ((Element) actualnode).setAttribute(aentry.getKey(), attrvalues[0]);
                                }
                            }
                        }

                        //Process second to last list elements and attributes (if more than once)
                        for (int ix = 1; ix < values.length; ix++) {
                            Element ngroup = document.createElement(keypart);
                            if (allattribs != null) {
                                for (Map.Entry<String, String> aentry : allattribs.entrySet()) {
                                    String[] attrvalues = aentry.getValue().split("\\|");
                                    if(attrvalues[ix-1]!=null){
                                        ngroup.setAttribute(aentry.getKey(), attrvalues[ix]);
                                    }
                                }
                            }
                            //append the xml tag
                            prevnode.appendChild(ngroup);
                            //append the real value of the (list) element (TextNode = value between tags)
                            ngroup.appendChild(document.createTextNode(values[ix]));
                        }
                    }
                }
            }

            //write the - in memory created - xml document to a file
            try (FileOutputStream outpt = new FileOutputStream(outputfile)) {
                TransformerFactory tfactory = TransformerFactory.newInstance();
                try {
                    tfactory.setAttribute("indent-number", 4);
                } catch (IllegalArgumentException e) {
                }
                Transformer transformer = tfactory.newTransformer();

                initOutputProperties(transformer);

                transformer.setErrorListener(new ErrorListener() {
                    @Override
                    public void warning(TransformerException exception) throws TransformerException {
                        LOG.warn("Transformer warning!",exception);
                    }
                    @Override
                    public void error(TransformerException exception) throws TransformerException {
                        LOG.error("Transformer error!", exception);
                    }

                    @Override
                    public void fatalError(TransformerException exception) throws TransformerException {
                        error(exception);
                    }
                });

                //this last call does the job:
                transformer.transform(new DOMSource(document), new StreamResult(new OutputStreamWriter(outpt, "UTF-8")));

            } catch (IOException ioe) {
                throw ioe;
            }

        } catch (ParserConfigurationException | DOMException | TransformerException | IOException ex) {
            throw new XMLMapException(ex.getMessage(), ex);
        }

    }

    private void initOutputProperties(Transformer transformer) {
        Map<String, String> outprops = new HashMap<>();

        outprops.put(OutputKeys.METHOD, "xml");
        outprops.put(OutputKeys.MEDIA_TYPE, "text/xml");
        outprops.put(OutputKeys.ENCODING, "UTF-8");
        outprops.put(OutputKeys.INDENT, "yes");
        outprops.put("{http://xml.apache.org/xalan}indent-amount", "4");

        for (Map.Entry<String, String> entrySet : outprops.entrySet()) {
            try {
                transformer.setOutputProperty(entrySet.getKey(), entrySet.getValue());
            } catch (Exception ex) {
                LOG.warn("Unsupported attribute in writing XML: {}", ex.getMessage());
            }
        }
    }

    @Override
    public String getXMLEntryPoint() {
        return this.xmlEntryPoint;
    }

    @Override
    public String getXMLRootNodeName() {
        return this.xmlRootNodeName;
    }

    @Override
    public String getXMLLevelSeparator() {
        return this.levelSeparator;
    }

    @Override
    public Pattern getRegexPattern() {
        return this.regexpattern;
    }

    /**
     * @param rexpattern the regexpattern to set
     */
    public void setRegexPattern(Pattern rexpattern) {
        this.regexpattern = rexpattern;
    }

    /**
     * @param xmlEntryPoint the xmlEntryPoint to set
     */
    public void setXmlEntryPoint(String xmlEntryPoint) {
        this.xmlEntryPoint = xmlEntryPoint;
    }

    /**
     * @param xmlRootNodeName the xmlRootNodeName to set
     */
    public void setXmlRootNodeName(String xmlRootNodeName) {
        this.xmlRootNodeName = xmlRootNodeName;
    }

    /**
     * @param levelSeparator the levelSeparator to set
     */
    public void setLevelSeparator(String levelSeparator) {
        this.levelSeparator = levelSeparator;
    }
}
