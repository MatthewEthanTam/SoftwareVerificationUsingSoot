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

	/**
	 * Understanding the error, we first need to track when a file is initialized,
	 * Thus we look at the JInvokeStmts to detect when a file is initialized and
	 * when `.open()` or `.close()` are called.
	 * When a file is initialized we find the class name of the expression is
	 * `JSpecialInvokeExpr`, thus we need to track the file state. Thus, creating a
	 * FileStateFact that will be added to the `out` file set. Now from a file init,
	 * either an open or a close call can be called.
	 * 
	 * Thus, we need to track if a `.open()` or `.close()` is called on the file. We
	 * look at the `JVirtualInvokeExpr` to see if the method name is `.open()` or
	 * `.close()`. If it is, we need to update the file state.
	 * 
	 * If a `.open()` is called, we need to check where that the base of the virtual
	 * expression is contained in any of the files `out` set. Thus, if the base is
	 * in a FileStateFact in the `out` set, then a check is done to see the state of
	 * the file, if the file is in `Init` or `Close` state, then the file state is
	 * updated to `Open`.
	 * 
	 * Similarly, if a `.close()` is called, we need to check that the base of
	 * the virtual expression is contained in any of the files `out` set. Thus, if
	 * the base is in a FileStateFact in the `out` set, then a check is done to see
	 * the state of the file, if the file is in `Init` or `Open` state, then the
	 * file state is updated to `Close`.
	 * 
	 * We then want to see when new file is assigned to a variable. Thus, we look at
	 * the `JAssignStmt` to see if the right hand side is contained in the `out`
	 * files aliases,
	 * if it is, then we need to add the the left hand side to the files aliases.
	 * 
	 * Finally when a `JReturnVoidStmt` is called, we need to check if the files
	 * in the `out` set, are in the `Open` state. If they are, then we report a
	 * vulnerability.
	 * 
	 */

	@Override
	protected void flowThrough(Set<FileStateFact> in, Unit unit, Set<FileStateFact> out) {
		copy(in, out);
		prettyPrint(in, unit, out);
		String simpleClassName = unit.getClass().getSimpleName();
		switch (simpleClassName) {
			case "JInvokeStmt":
				InvokeExpr expression = ((InvokeStmt) unit).getInvokeExpr();
				String className = expression.getClass().getSimpleName();
				String methodName;
				Value base;
				switch (className) {
					case "JSpecialInvokeExpr":
						methodName = ((SpecialInvokeExpr) expression).getMethod().getName();
						// Checking if a init statement is called for the file and adding it to the `out`
						// set
						if (methodName.equals("<init>")) {
							Set<Value> stackAndInit = new HashSet<Value>();
							base = ((SpecialInvokeExpr) expression).getBase();
							stackAndInit.add(base);
							FileStateFact FileFact = new FileStateFact(stackAndInit, FileState.Init);
							out.add(FileFact);
						}
						break;
					case "JVirtualInvokeExpr":
						methodName = ((VirtualInvokeExpr) expression).getMethod().getName();

						if (methodName.equals("open")) {
							base = ((VirtualInvokeExpr) expression).getBase();
							for (FileStateFact i : out) {
								// if File is at state `Init`/`Close`, then change to `Open` state (init -> open, close
								// -> open)
								if (i.containsAlias(base)
										&& (i.getState() == FileState.Init || i.getState() == FileState.Close)) {
									i.updateState(FileState.Open);
								}
							}
						} else if (methodName.equals("close")) {
							base = ((VirtualInvokeExpr) expression).getBase();
							for (FileStateFact i : out) {
								// if File is at state `Open`/`Init`, then can change to `Close` state (init -> close, open
								// -> close))
								if (i.containsAlias(base)
										&& (i.getState() == FileState.Init || i.getState() == FileState.Open)) {
									i.updateState(FileState.Close);
								}
							}
						}
						break;
					default:
						// Do nothing
				}
				break;
			case "JAssignStmt":
				for (FileStateFact i : out) {
					if (i.containsAlias(((AssignStmt) unit).getRightOp())) {
						i.addAlias(((AssignStmt) unit).getLeftOp());
					}
				}
				break;
			case "JReturnVoidStmt":
				Stmt stmt = (Stmt) unit;
				for (FileStateFact i : out) {
					if (i.isOpened()) {
						reporter.reportVulnerability(method.getName(), stmt);
					}
				}
				break;
			default:
				// Do nothing

		}

	}
	// Didn't use these methods but checked if they worked.
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
