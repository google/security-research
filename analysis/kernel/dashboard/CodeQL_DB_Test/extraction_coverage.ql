/**
 * @name Compilation vs. Extraction Coverage & Subsystem Parity
 * @description Measures intrinsic extraction completeness for a single CodeQL database:
 *              what percentage of .c files compiled during the build produced valid
 *              AST function definitions, globally and across core subsystems.
 * @kind table
 * @id cpp/kernel-db-test/extraction-coverage
 */

import cpp

predicate isSubsystem(string subsys) {
  subsys in ["fs", "net", "mm", "kernel", "security", "drivers", "arch"]
}

predicate isSubsystemFile(File f, string subsys) {
  isSubsystem(subsys) and
  exists(string rel | rel = f.getRelativePath() |
    subsys = "fs" and rel.matches("fs/%")
    or
    subsys = "net" and rel.matches("net/%")
    or
    subsys = "mm" and rel.matches("mm/%")
    or
    subsys = "kernel" and rel.matches("kernel/%")
    or
    subsys = "security" and rel.matches("security/%")
    or
    subsys = "drivers" and rel.matches("drivers/%")
    or
    subsys = "arch" and rel.matches("arch/%")
  )
}

int compiledCount(string subsys) {
  isSubsystem(subsys) and
  result = count(File f |
    f.getExtension() = "c" and
    isSubsystemFile(f, subsys) and
    exists(Compilation c | c.getAFileCompiled() = f)
  )
}

int extractedCount(string subsys) {
  isSubsystem(subsys) and
  result = count(File f |
    f.getExtension() = "c" and
    isSubsystemFile(f, subsys) and
    exists(Compilation c | c.getAFileCompiled() = f) and
    exists(Function fn | fn.getFile() = f and fn.hasDefinition() and exists(fn.getBlock()))
  )
}

int definedFuncsCount(string subsys) {
  isSubsystem(subsys) and
  result = count(Function fn |
    isSubsystemFile(fn.getFile(), subsys) and
    fn.hasDefinition() and
    exists(fn.getBlock())
  )
}

from
  string scope,
  int compiledCFiles,
  int extractedCFiles,
  int droppedCFiles,
  int definedFunctions
where
  (
    (
      scope = "GLOBAL" and
      compiledCFiles = count(File f | f.getExtension() = "c" and exists(Compilation c | c.getAFileCompiled() = f)) and
      extractedCFiles = count(File f |
        f.getExtension() = "c" and
        exists(Compilation c | c.getAFileCompiled() = f) and
        exists(Function fn | fn.getFile() = f and fn.hasDefinition() and exists(fn.getBlock()))
      ) and
      definedFunctions = count(Function fn | fn.hasDefinition() and exists(fn.getBlock()))
    )
    or
    (
      isSubsystem(scope) and
      compiledCFiles = compiledCount(scope) and
      extractedCFiles = extractedCount(scope) and
      definedFunctions = definedFuncsCount(scope)
    )
  ) and
  droppedCFiles = compiledCFiles - extractedCFiles
select
  scope,
  compiledCFiles,
  extractedCFiles,
  droppedCFiles,
  definedFunctions
