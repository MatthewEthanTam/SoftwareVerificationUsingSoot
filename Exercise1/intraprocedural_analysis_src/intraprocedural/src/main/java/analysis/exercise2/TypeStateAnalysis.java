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
		prettyPrint(in, unit, out);
		if (unit instanceof InvokeStmt) {
			InvokeExpr expression = ((InvokeStmt) unit).getInvokeExpr();
			if (expression instanceof SpecialInvokeExpr ) {
				String methodName = ((SpecialInvokeExpr) expression).getMethod().getName();
				Value base = ((SpecialInvokeExpr) expression).getBase();
				// Checking if a init statement is called for the file and adding it to the out set
				if (methodName.equals("<init>")) {
					Set<Value> stackAndInit = new HashSet<Value>();
					stackAndInit.add(base);
					FileStateFact FileFact= new FileStateFact(stackAndInit, FileState.Init);
					out.add(FileFact);
				}
			} else if (expression instanceof VirtualInvokeExpr) {
				// Changing state if an open/close statement is called
				String methodName = ((VirtualInvokeExpr) expression).getMethod().getName();
				Value base = ((VirtualInvokeExpr) expression).getBase();
				if (methodName.equals("open")) {
					for(FileStateFact i : out) {
						// if File is at state Init/Close File can change to Open (init -> open, close -> open)
						if (i.containsAlias(base) && (i.getState() == FileState.Init || i.getState() == FileState.Close)) {
							i.updateState(FileState.Open);
						}
					}
				} else if (methodName.equals("close")) {
					for(FileStateFact i : out) {
						// if File is at state Open/Init File can change to Close (init -> close, open -> close)) 
						if (i.containsAlias(base) && (i.getState() == FileState.Init ||i.getState() == FileState.Open)) {
							i.updateState(FileState.Close);
						}
					}
				}
			}
			// If FileState contains the alias of the right operator then add the alias of the left operator to the FileStateFact
		} else if (unit instanceof AssignStmt) {
				for (FileStateFact i: out){
					if (i.containsAlias(((AssignStmt) unit).getRightOp())) {
						i.addAlias(((AssignStmt) unit).getLeftOp());
					}
				}
			// If a FileStateFact is still open then report a vulnerability
		} else if (unit instanceof ReturnVoidStmt) {
			Stmt stmt = (Stmt) unit;
			for (FileStateFact i: out){
				if (i.isOpened()) {
					reporter.reportVulnerability(method.getName(), stmt);
				}
			}
		}
		
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
