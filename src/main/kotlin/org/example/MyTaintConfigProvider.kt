package org.example

import pascal.taie.World
import pascal.taie.analysis.pta.plugin.taint.*
import pascal.taie.language.annotation.ArrayElement
import pascal.taie.language.annotation.StringElement
import pascal.taie.language.classes.ClassHierarchy
import pascal.taie.language.type.TypeSystem
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import java.io.File

class MyTaintConfigProvider(val hierarchy: ClassHierarchy, val typeSystem: TypeSystem) :
    TaintConfigProvider(hierarchy, typeSystem) {

    companion object {
        val ALL_PUBLIC_METHODS_ARE_SOURCES = false;
    }

    override fun sources(): MutableList<Source> {
        val sources = mutableListOf<Source>()

        if (ALL_PUBLIC_METHODS_ARE_SOURCES) {
            for (cls in hierarchy.allClasses()) {
                if (!cls.name.startsWith("org.joychou")) continue
                for (method in cls.declaredMethods) {
                    if (method.isPublic) {
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
                }
                for (field in cls.declaredFields) {
                    if (field.isPublic) {
                        sources.add(
                            FieldSource(
                                field,
                                field.type,
                            )
                        )
                    }
                }
            }
        } else {
            for (cls in hierarchy.allClasses()) {
                for (method in cls.declaredMethods) {
                    if (method.isPublic) {
                        for (i in 0..<method.paramCount) {
                            if (method.getParamAnnotations(i).find {
                                    it.type == "org.springframework.web.bind.annotation.RequestParam"
                                } != null) {
                                sources.add(
                                    ParamSource(
                                        method,
                                        IndexRef(IndexRef.Kind.VAR, i, null),
                                        method.getParamType(i),
                                    )
                                )
                            }
                        }
                    }
                }
            }
        }

        return sources
    }

    override fun transfers(): MutableList<TaintTransfer> {
        val transfers = mutableListOf<TaintTransfer>()
        return transfers
    }

    data class UnsafeMappedQuery(
        val className: String,
        val methodName: String,
        val unsafeParamName: String?
    )

    private fun findInjections(sql: String): List<String?> {
        val pattern = Regex("\\$\\{\\s*([\\w_]+)\\s*}")
        return pattern.findAll(sql).map {
            val name = it.groupValues[1]
            if (name == "_parameter") {
                null
            } else {
                name
            }
        }.toList()
    }

    private fun findUnsafeQueries(world: World): List<UnsafeMappedQuery> {
        val queries = mutableListOf<UnsafeMappedQuery>()
        for (cp in world.options.classPath) {
            val f = File(cp)
            if (f.isDirectory) {
                f.walk().filter { it.isFile && it.extension == "xml" }.forEach { xmlFile ->
                    runCatching {
                        val doc = DocumentBuilderFactory.newInstance()
                            .newDocumentBuilder()
                            .parse(xmlFile)
                        val mapperEl = doc.documentElement
                        val namespace = mapperEl.getAttribute("namespace")
                        fun traverse(node: org.w3c.dom.Node, currentId: String?) {
                            if (node is Element) {
                                var stmtId = currentId
                                if (node.tagName in listOf("select", "insert", "update", "delete")) {
                                    stmtId = node.getAttribute("id")
                                }
                                stmtId?.let { id ->
                                    val sql = node.textContent
                                    for (unsafeParamName in findInjections(sql)) {
                                        queries.add(
                                            UnsafeMappedQuery(
                                                className = namespace,
                                                methodName = id,
                                                unsafeParamName = unsafeParamName
                                            )
                                        )
                                    }
                                }
                                val children = node.childNodes
                                for (i in 0 until children.length) {
                                    traverse(children.item(i), stmtId)
                                }
                            }
                        }
                        traverse(mapperEl, null)
                    }
                }
            } else if (f.isFile && f.extension == "jar") {
                // optionally handle jar entries...
            }
        }
        return queries
    }

    override fun sinks(): MutableList<Sink> {
        val sinks = mutableListOf<Sink>()

        val unsafeQueries = findUnsafeQueries(World.get())

        for (cls in hierarchy.allClasses()) {
            if (!cls.hasAnnotation("org.apache.ibatis.annotations.Mapper")) continue
            for (method in cls.declaredMethods) {
                val unsafeParamNames = mutableListOf<String?>()

                val dangerousAnnotations = listOf(
                    "org.apache.ibatis.annotations.Select",
                    "org.apache.ibatis.annotations.Update",
                    "org.apache.ibatis.annotations.Delete",
                    "org.apache.ibatis.annotations.Insert"
                )

                for (annotation in method.annotations) {
                    if (!dangerousAnnotations.contains(annotation.type)) continue
                    annotation.getElement("value")?.let { value ->
                        if (value is ArrayElement) {
                            val sql = (value.elements[0] as StringElement).value
                            for (injection in findInjections(sql)) {
                                unsafeParamNames.add(injection)
                            }
                        }
                    }
                }

                for (injection in unsafeQueries) {
                    if (injection.className == cls.name && injection.methodName == method.name) {
                        unsafeParamNames.add(injection.unsafeParamName)
                    }
                }

                if (method.paramCount == 1 && unsafeParamNames.contains(null)) {
                    sinks.add(
                        Sink(
                            method,
                            IndexRef(IndexRef.Kind.VAR, 0, null),
                        )
                    )
                    continue
                }

                for (i in 0..<method.paramCount) {
                    if (!method.hasParamAnnotation(
                            i,
                            "org.apache.ibatis.annotations.Param"
                        )
                    ) continue
                    for (annotation in method.getParamAnnotations(i)) {
                        if (annotation.type != "org.apache.ibatis.annotations.Param") continue
                        annotation.getElement("value")?.let { value ->
                            if (value is StringElement) {
                                val paramName = value.value
                                if (unsafeParamNames.contains(paramName)) {
                                    sinks.add(
                                        Sink(
                                            method,
                                            IndexRef(IndexRef.Kind.VAR, i, null),
                                        )
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        return sinks
    }

    override fun sanitizers(): MutableList<ParamSanitizer> {
        return mutableListOf()
    }
}
