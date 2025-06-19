package org.example

import pascal.taie.World
import pascal.taie.analysis.pta.plugin.taint.*
import pascal.taie.language.annotation.ArrayElement
import pascal.taie.language.annotation.StringElement
import pascal.taie.language.classes.ClassHierarchy
import pascal.taie.language.type.TypeSystem
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.w3c.dom.Document
import org.w3c.dom.Node
import pascal.taie.analysis.pta.plugin.util.InvokeUtils
import java.io.File
import java.util.jar.JarFile

class TestConfigProvider(val hierarchy: ClassHierarchy, val typeSystem: TypeSystem) :
    TaintConfigProvider(hierarchy, typeSystem) {

    override fun sources(): MutableList<Source> {
        val sources = mutableListOf<Source>()

        for (cls in hierarchy.allClasses()) {
            if (cls.name != "Main") continue;
            for (method in cls.declaredMethods) {
                if (method.name.startsWith("entry")) {
                    for (i in 0..<method.paramCount) {
                        sources.add(
                            ParamSource(
                                method,
                                IndexRef(IndexRef.Kind.VAR, i, null),
                                method.getParamType(i),
                            )
                        )
                    }
                }
                // if (method.name.startsWith("source")) {
                //     sources.add(
                //         CallSource(
                //             method,
                //             IndexRef(IndexRef.Kind.VAR, InvokeUtils.RESULT, null),
                //             method.returnType,
                //         )
                //     )
                // }
            }
        }

        return sources
    }

    override fun transfers(): MutableList<TaintTransfer> {
        val transfers = mutableListOf<TaintTransfer>()
        return transfers
    }

    override fun sinks(): MutableList<Sink> {
        val sinks = mutableListOf<Sink>()

        for (cls in hierarchy.allClasses()) {
            if (cls.name != "Main") continue
            for (method in cls.declaredMethods) {
                if (method.name != "sink") continue

                for (i in 0..<method.paramCount) {
                    sinks.add(
                        Sink(
                            method,
                            IndexRef(IndexRef.Kind.VAR, i, null),
                        )
                    )
                }
            }
        }

        return sinks
    }

    override fun sanitizers(): MutableList<ParamSanitizer> {
        return mutableListOf()
    }
}
