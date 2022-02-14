#!/bin/sh
java -Dcom.sun.jndi.ldap.object.trustURLCodebase=true -classpath .:ashhax:log4j-core-2.15.0.jar:log4j-api-2.15.0.jar:commons-collections-3.1.jar poc $1
