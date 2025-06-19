#!/usr/bin/env bash

mkdir -p /tmp/classes &&
/usr/lib/jvm/java-1.8.0-openjdk-amd64/bin/javac Main.java -d /tmp/classes &&
./gradlew :fatJar &&
java \
  -jar build/tai-e-all-0.5.2-SNAPSHOT.jar \
  -a "pta=cs:2-type;distinguish-string-constants:all;merge-string-objects:false;merge-string-builders:false;plugins:[org.example.TestExtraEntryPoints];taint-config:taint-config;taint-config-providers:[org.example.TestConfigProvider]" \
  -a "ir-dumper" \
  -java 8 \
  -ap \
  -cp /tmp/classes \
  --input-classes=Main
