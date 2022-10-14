package analysis.exercise2;
import analysis.FileState;
import java.util.Set;
import java.util.HashSet;
import analysis.FileStateFact;
import analysis.ForwardAnalysis;
import analysis.VulnerabilityReporter;
import java_cup.lalr_item;
import soot.jimple.*;
import soot.*;

public class TypeStateAnalysis extends ForwardAnalysis<Set<FileStateFact>> {

	public TypeStateAnalysis(Body body, VulnerabilityReporter reporter) {
		super(body, reporter);
	}

	@Override
	protected void flowThrough(Set<FileStateFact> in, Unit unit, Set<FileStateFact> out) {
		copy(in, out);
		// CHECKING INIT  
		if (unit instanceof InvokeStmt) {
			InvokeExpr expression = ((InvokeStmt) unit).getInvokeExpr();
			if (expression instanceof SpecialInvokeExpr ) {
				String methodName = ((SpecialInvokeExpr) expression).getMethod().getName();
				Value base = ((SpecialInvokeExpr) expression).getBase();
				// Checking if a init statement is called for the file and adding it to the out set
				if (methodName.equals("<init>")) {
					Set<Value> stackAndInit = new HashSet<Value>();
					stackAndInit.add(base);
					FileStateFact fact= new FileStateFact(stackAndInit, FileState.Init);
					out.add(fact);
				}
			} else if (expression instanceof VirtualInvokeExpr) {

				String methodName = ((VirtualInvokeExpr) expression).getMethod().getName();
				Value base = ((VirtualInvokeExpr) expression).getBase();
				if (methodName.equals("open")) {
					for(FileStateFact i : out) {
						if (i.containsAlias(base) && (i.getState() == FileState.Init || i.getState() == FileState.Close)) {
							i.updateState(FileState.Open);
						}
							
						}
					}
				}
			}
		

		// if (unit instanceof InvokeStmt) {
		// 	InvokeStmt invokeStmt = (InvokeStmt) unit;
		// 	InvokeExpr expr = invokeStmt.getInvokeExpr();
		// 	if (expr instanceof SpecialInvokeExpr) {
		// 		SpecialInvokeExpr specialInvoke = (SpecialInvokeExpr) expr;
		// 		Value base = specialInvoke.getBase();
		// 		SootMethod method = specialInvoke.getMethod();
		// 		if (method.getSignature().equals("<target.exercise2.File: void <init>()>")) {
		// 			Set<Value> aliases = new HashSet<Value>();
		// 			aliases.add(base);
		// 			FileStateFact fact= new FileStateFact(aliases, FileState.Init);
		// 			out.add(fact);
		// 		}
		// 	} else if (expr instanceof VirtualInvokeExpr) {
		// 		VirtualInvokeExpr virtualInvoke = (VirtualInvokeExpr) expr;
		// 		Value base = virtualInvoke.getBase();
		// 		SootMethod method = virtualInvoke.getMethod();
		// 		if (method.getSignature().equals("<target.exercise2.File: void open()>")) {
		// 			for (FileStateFact fact:out) {
		// 				if (fact.containsAlias(base)) {
		// 					if (fact.getState().equals(FileState.Init) || fact.getState().equals(FileState.Close))
		// 						fact.updateState(FileState.Open);
		// 				}
		// 			}
		// 		} else if (method.getSignature().equals("<target.exercise2.File: void close()>")) {
		// 			for (FileStateFact fact: out){
		// 				if (fact.containsAlias(base)) {
		// 					if (fact.getState().equals(FileState.Open))
		// 						fact.updateState(FileState.Close);
		// 				}
		// 			}
		// 		}

		// 	}
		// } else if (unit instanceof AssignStmt) {
		// 	AssignStmt assignStmt = (AssignStmt) unit;
		// 	Value leftOp = assignStmt.getLeftOp();
		// 	Value rightOp = assignStmt.getRightOp();
		// 	for (FileStateFact fact: out){
		// 		if (fact.containsAlias(rightOp)) {
		// 			fact.addAlias(leftOp);
		// 		}
		// 	}
		// } else if (unit instanceof ReturnVoidStmt) {
		// 	for (FileStateFact fact: out){
		// 		if (fact.isOpened()) {
		// 			reporter.reportVulnerability(this.method.getSignature(), (Stmt) unit);
		// 		}
		// 	}
		// }
		prettyPrint(in, unit, out);
	}

	@Override
	protected Set<FileStateFact> newInitialFlow() {
		return new HashSet<FileStateFact>();
	}
	
	@Override
	protected void copy(Set<FileStateFact> source, Set<FileStateFact> dest) {
		Set<FileStateFact> copyOfSource = Set.copyOf(source);
		dest.addAll(copyOfSource);
	}

	@Override
	protected void merge(Set<FileStateFact> in1, Set<FileStateFact> in2, Set<FileStateFact> out) {
		out.addAll(in1);
		out.addAll(in2);
	}

}
