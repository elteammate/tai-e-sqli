package org.example

import pascal.taie.analysis.pta.core.cs.context.Context
import pascal.taie.analysis.pta.core.cs.element.CSObj
import pascal.taie.analysis.pta.core.solver.Solver
import pascal.taie.analysis.pta.plugin.Plugin
import pascal.taie.ir.stmt.Invoke

class TraceUnresolvedCalls : Plugin {
    lateinit var theSolver: Solver

    override fun setSolver(solver: Solver?) {
        if (solver != null) {
            theSolver = solver
        }
    }

    override fun onUnresolvedCall(recv: CSObj?, context: Context?, invoke: Invoke?) {
        println("Unresolved call: ${invoke?.methodRef?.subsignature} in context: $context")
    }
}
