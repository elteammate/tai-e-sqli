```bash
#!/usr/bin/env bash

./gradlew :fatJar &&
java \
  -jar build/tai-e-all-0.5.1.jar \
  -a "pta=cs:1-call;distinguish-string-constants:all;merge-string-objects:false;merge-string-builders:false;plugins:[org.example.ExtraEntryPoints,org.example.TraceUnresolvedCalls];taint-config:taint-config;taint-config-providers:[org.example.MyTaintConfigProvider]" \
  -a "ir-dumper" \
  -java 8 \
  -ap \
  -cp ../java-sec-code/target/classes \
  --input-classes=org.joychou.controller.SQLI
```
