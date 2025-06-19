package org.example;

import pascal.taie.World;
import pascal.taie.analysis.pta.core.solver.DeclaredParamProvider;
import pascal.taie.analysis.pta.core.solver.EntryPoint;
import pascal.taie.analysis.pta.core.solver.Solver;
import pascal.taie.analysis.pta.plugin.Plugin;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;

public class TestExtraEntryPoints implements Plugin {
    private Solver theSolver;

    @Override
    public void setSolver(Solver solver) {
        if (solver != null) {
            theSolver = solver;
        }
        Plugin.super.setSolver(solver);
    }

    @Override
    public void onStart() {
        for (JClass cls : World.get().getClassHierarchy().allClasses().toList()) {
            if (!cls.getName().equals("Main")) continue;
            for (JMethod method : cls.getDeclaredMethods()) {
                if (method.getName().startsWith("entry")) {
                    theSolver.addEntryPoint(new EntryPoint(
                            method,
                            new DeclaredParamProvider(method, theSolver.getHeapModel(), 2)
                    ));
                }
            }
        }
    }
}

