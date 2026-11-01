# Reproducibility guide

## What is included
Original Java source, XML policy, three example text data files and four screenshots.

## Prerequisites
- Java JDK (exact tested version not specified by original artifact).
- External Java package `orbac.*` (artifact/JAR and version not provided).
- A text trace named `PCAP_Attack.txt` with the expected packet-listing columns (not included).
- For end-to-end evaluation: an Open5GS environment and its deployment configuration (not included).

## Source compilation preparation
The original filename is `SCP_Module.java` but its public class is `OrBacPolicy_Open5GS`. Copy it under the matching filename before compiling:

```bash
mkdir -p build/source build/classes
cp src/java/SCP_Module.java build/source/OrBacPolicy_Open5GS.java
# Replace /path/to/orbac.jar with the actual dependency provided by its owner.
javac -cp /path/to/orbac.jar -d build/classes build/source/OrBacPolicy_Open5GS.java
```

The code uses relative file paths such as `5g`, `PCAP_Attack.txt` and writes intermediate outputs in the current working directory. Run it in a dedicated working directory and copy the policy there under its original name `5g`:

```bash
mkdir -p build/run
cp policies/orbac/5g.xml build/run/5g
# Add the actual PCAP_Attack.txt input to build/run/ before running.
cd build/run
java -cp ../classes:/path/to/orbac.jar OrBacPolicy_Open5GS
```

On Windows replace the Java classpath separator `:` with `;`. The command cannot run successfully without the missing dependency and trace. Other required resources may be discovered by reviewing the Java implementation.

## Verification boundaries
- XML parsing can be checked independently using Python's standard library.
- Source compilation and runtime behavior have **not** been validated against the missing OrBAC library.
- Screenshots should not be treated as quantified measurements.


