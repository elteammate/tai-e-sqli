package org.example

import pascal.taie.World
import pascal.taie.analysis.pta.core.solver.DeclaredParamProvider
import pascal.taie.analysis.pta.core.solver.EntryPoint
import pascal.taie.analysis.pta.core.solver.Solver
import pascal.taie.analysis.pta.plugin.Plugin

class TestExtraEntryPoints : Plugin {
    private lateinit var theSolver: Solver

    override fun setSolver(solver: Solver?) {
        if (solver != null) {
            theSolver = solver
        }
        super.setSolver(solver)
    }

    override fun onStart() {
        for (cls in World.get().classHierarchy.allClasses()) {
            if (cls.name != "Main") continue
            for (method in cls.declaredMethods) {
                if (method.name.startsWith("entry")) {
                // if (method.name == "entry") {
                    theSolver.addEntryPoint(EntryPoint(
                        method,
                        DeclaredParamProvider(method, theSolver.heapModel, 2)
                    ))
                }
            }
        }
    }
}
