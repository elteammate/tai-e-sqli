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
        for (cls in World.get().classHierarchy.allClasses()) {
            for (method in cls.declaredMethods) {
                if (method.hasAnnotation("org.springframework.web.bind.annotation.RequestMapping") ||
                    method.hasAnnotation("org.springframework.web.bind.annotation.GetMapping")) {
                    theSolver.addEntryPoint(EntryPoint(
                        method,
                        DeclaredParamProvider(method, theSolver.heapModel, 2)
                    ))
                }
            }
        }
    }
}
