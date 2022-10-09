package analysis.exercise2;
import analysis.FileState;
import java.util.Set;
import java.util.HashSet;
import analysis.FileStateFact;
import analysis.ForwardAnalysis;
import analysis.VulnerabilityReporter;
import soot.jimple.*;
import soot.*;

public class TypeStateAnalysis extends ForwardAnalysis<Set<FileStateFact>> {

	public TypeStateAnalysis(Body body, VulnerabilityReporter reporter) {
		super(body, reporter);
	}

	@Override
	protected void flowThrough(Set<FileStateFact> in, Unit unit, Set<FileStateFact> out) {
		copy(in, out);
		if (unit instanceof InvokeStmt) {
			InvokeStmt invokeStmt = (InvokeStmt) unit;
			InvokeExpr expr = invokeStmt.getInvokeExpr();
			if (expr instanceof SpecialInvokeExpr) {
				SpecialInvokeExpr specialInvoke = (SpecialInvokeExpr) expr;
				Value base = specialInvoke.getBase();
				SootMethod method = specialInvoke.getMethod();
				if (method.getSignature().equals("<target.exercise2.File: void <init>()>")) {
					Set<Value> aliases = new HashSet<Value>();
					aliases.add(base);
					FileStateFact fact= new FileStateFact(aliases, FileState.Init);
					out.add(fact);
				}
			} else if (expr instanceof VirtualInvokeExpr) {
				VirtualInvokeExpr virtualInvoke = (VirtualInvokeExpr) expr;
				Value base = virtualInvoke.getBase();
				SootMethod method = virtualInvoke.getMethod();
				if (method.getSignature().equals("<target.exercise2.File: void open()>")) {
					for (FileStateFact fact:out) {
						if (fact.containsAlias(base)) {
							if (fact.getState().equals(FileState.Init) || fact.getState().equals(FileState.Close))
								fact.updateState(FileState.Open);
						}
					}
				} else if (method.getSignature().equals("<target.exercise2.File: void close()>")) {
					for (FileStateFact fact: out){
						if (fact.containsAlias(base)) {
							if (fact.getState().equals(FileState.Open))
								fact.updateState(FileState.Close);
						}
					}
				}

			}
		} else if (unit instanceof AssignStmt) {
			AssignStmt assignStmt = (AssignStmt) unit;
			Value leftOp = assignStmt.getLeftOp();
			Value rightOp = assignStmt.getRightOp();
			for (FileStateFact fact: out){
				if (fact.containsAlias(rightOp)) {
					fact.addAlias(leftOp);
				}
			}
		} else if (unit instanceof ReturnVoidStmt) {
			for (FileStateFact fact: out){
				if (fact.isOpened()) {
					reporter.reportVulnerability(this.method.getSignature(), (Stmt) unit);
				}
			}
		}
		prettyPrint(in, unit, out);
	}

	@Override
	protected Set<FileStateFact> newInitialFlow() {
		return new HashSet<FileStateFact>();
	}

	@Override
	protected void copy(Set<FileStateFact> source, Set<FileStateFact> dest) {
		for(FileStateFact f: source)
		{
			dest.add(f.copy());
		}
	}

	@Override
	protected void merge(Set<FileStateFact> in1, Set<FileStateFact> in2, Set<FileStateFact> out) {
		for(FileStateFact f: in1)
		{
			if(!out.contains(f))
				out.add(f);
		}
		for(FileStateFact f: in2)
		{
			if(!out.contains(f))
				out.add(f);
		}
	}

}
