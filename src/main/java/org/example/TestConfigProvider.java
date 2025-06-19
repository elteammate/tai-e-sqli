package org.example;

import pascal.taie.analysis.pta.plugin.taint.*;
import pascal.taie.language.classes.ClassHierarchy;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.TypeSystem;

import java.util.ArrayList;
import java.util.List;

public class TestConfigProvider extends TaintConfigProvider {

    public TestConfigProvider(ClassHierarchy hierarchy, TypeSystem typeSystem) {
        super(hierarchy, typeSystem);
    }

    @Override
    public List<Source> sources() {
        List<Source> sources = new ArrayList<>();
        for (JClass cls : hierarchy.allClasses().toList()) {
            if (!cls.getName().equals("Main")) continue;
            for (JMethod method : cls.getDeclaredMethods()) {
                if (method.getName().startsWith("entry")) {
                    for (int i = 0; i < method.getParamCount(); i++) {
                        sources.add(
                                new ParamSource(
                                        method,
                                        new IndexRef(IndexRef.Kind.VAR, i, null),
                                        method.getParamType(i)
                                )
                        );
                    }
                }
            }
        }
        return sources;
    }

    @Override
    public List<TaintTransfer> transfers() {
        return new ArrayList<>();
    }

    @Override
    public List<Sink> sinks() {
        List<Sink> sinks = new ArrayList<>();
        for (JClass cls : hierarchy.allClasses().toList()) {
            if (!cls.getName().equals("Main")) continue;
            for (JMethod method : cls.getDeclaredMethods()) {
                if (!method.getName().equals("sink")) continue;
                for (int i = 0; i < method.getParamCount(); i++) {
                    sinks.add(
                            new Sink(
                                    method,
                                    new IndexRef(IndexRef.Kind.VAR, i, null)
                            )
                    );
                }
            }
        }
        return sinks;
    }

    @Override
    public List<ParamSanitizer> sanitizers() {
        return new ArrayList<>();
    }
}

