---
title: 'SnakeYaml: Constructor Deserialization Remote Code Execution'
severity: High
ghsa_id: GHSA-mjmj-j48q-9wg2
cve_id: CVE-2022-1471
weaknesses: []
products:
- ecosystem: SnakeYaml
  package_name: Constructor
  affected_versions: '1.30'
  patched_versions: ''
cvss: null
credits:
- github_user_id: justintaft
  name: Justin Taft
  avatar: https://avatars.githubusercontent.com/u/8340498?s=40&v=4
- github_user_id: securisec
  name: securisec
  avatar: https://avatars.githubusercontent.com/u/22226823?s=40&v=4
---

### Summary
SnakeYaml's `Constructor` class, which inherits from `SafeConstructor`, allows
any type be deserialized given the following line:

new Yaml(new Constructor(TestDataClass.class)).load(yamlContent);

Types do not have to match the types of properties in the
target class. A `ConstructorException` is thrown, but only after a malicious
payload is deserialized.

### Severity
High, lack of type checks during deserialization allows remote code execution.

### Proof of Concept
Execute `bash run.sh`. The PoC uses Constructor to deserialize a payload
for RCE. RCE is demonstrated by using a payload which performs a http request to
http://127.0.0.1:8000.

Example output of successful run of proof of concept:

```
$ bash run.sh

[+] Downloading snakeyaml if needed
[+] Starting mock HTTP server on 127.0.0.1:8000 to demonstrate RCE
nc: no process found
[+] Compiling and running Proof of Concept, which a payload that sends a HTTP request to mock web server.
[+] An exception is expected.
Exception:
Cannot create property=payload for JavaBean=Main$TestDataClass@3cbbc1e0
 in 'string', line 1, column 1:
    payload: !!javax.script.ScriptEn ... 
    ^
Can not set java.lang.String field Main$TestDataClass.payload to javax.script.ScriptEngineManager
 in 'string', line 1, column 10:
    payload: !!javax.script.ScriptEngineManag ... 
             ^

	at org.yaml.snakeyaml.constructor.Constructor$ConstructMapping.constructJavaBean2ndStep(Constructor.java:291)
	at org.yaml.snakeyaml.constructor.Constructor$ConstructMapping.construct(Constructor.java:172)
	at org.yaml.snakeyaml.constructor.Constructor$ConstructYamlObject.construct(Constructor.java:332)
	at org.yaml.snakeyaml.constructor.BaseConstructor.constructObjectNoCheck(BaseConstructor.java:230)
	at org.yaml.snakeyaml.constructor.BaseConstructor.constructObject(BaseConstructor.java:220)
	at org.yaml.snakeyaml.constructor.BaseConstructor.constructDocument(BaseConstructor.java:174)
	at org.yaml.snakeyaml.constructor.BaseConstructor.getSingleData(BaseConstructor.java:158)
	at org.yaml.snakeyaml.Yaml.loadFromReader(Yaml.java:491)
	at org.yaml.snakeyaml.Yaml.load(Yaml.java:416)
	at Main.main(Main.java:37)
Caused by: java.lang.IllegalArgumentException: Can not set java.lang.String field Main$TestDataClass.payload to javax.script.ScriptEngineManager
	at java.base/jdk.internal.reflect.UnsafeFieldAccessorImpl.throwSetIllegalArgumentException(UnsafeFieldAccessorImpl.java:167)
	at java.base/jdk.internal.reflect.UnsafeFieldAccessorImpl.throwSetIllegalArgumentException(UnsafeFieldAccessorImpl.java:171)
	at java.base/jdk.internal.reflect.UnsafeObjectFieldAccessorImpl.set(UnsafeObjectFieldAccessorImpl.java:81)
	at java.base/java.lang.reflect.Field.set(Field.java:780)
	at org.yaml.snakeyaml.introspector.FieldProperty.set(FieldProperty.java:44)
	at org.yaml.snakeyaml.constructor.Constructor$ConstructMapping.constructJavaBean2ndStep(Constructor.java:286)
	... 9 more
[+] Dumping Received HTTP Request. Will not be empty if PoC worked
GET /proof-of-concept HTTP/1.1
User-Agent: Java/11.0.14
Host: localhost:8000
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive
```

### Further Analysis
Potential mitigations include, leveraging SnakeYaml's SafeConstructor while parsing untrusted content.

See https://bitbucket.org/snakeyaml/snakeyaml/issues/561/cve-2022-1471-vulnerability-in#comment-64581479 for discussion on the subject.

### Timeline
**Date reported**: 4/11/2022
**Date fixed**: 
**Date disclosed**: 10/13/2022