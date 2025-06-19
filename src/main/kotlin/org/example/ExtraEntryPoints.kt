package org.example

import pascal.taie.World
import pascal.taie.analysis.pta.core.solver.DeclaredParamProvider
import pascal.taie.analysis.pta.core.solver.EntryPoint
import pascal.taie.analysis.pta.core.solver.Solver
import pascal.taie.analysis.pta.plugin.Plugin

class ExtraEntryPoints : Plugin {
    private lateinit var theSolver: Solver

    override fun setSolver(solver: Solver?) {
        if (solver != null) {
            theSolver = solver
        }
        super.setSolver(solver)
    }

    override fun onStart() {
        val mappingAnnos = listOf(
            "org.springframework.web.bind.annotation.RequestMapping",
            "org.springframework.web.bind.annotation.GetMapping",
            "org.springframework.web.bind.annotation.PostMapping",
            "org.springframework.web.bind.annotation.PutMapping",
            "org.springframework.web.bind.annotation.DeleteMapping",
            "org.springframework.web.bind.annotation.PatchMapping"
        )
        for (cls in World.get().classHierarchy.allClasses()) {
            for (method in cls.declaredMethods) {
                if (mappingAnnos.any { method.hasAnnotation(it) }) {
                    theSolver.addEntryPoint(EntryPoint(
                        method,
                        DeclaredParamProvider(method, theSolver.heapModel, 2)
                    ))
                }
            }
        }
    }
}
