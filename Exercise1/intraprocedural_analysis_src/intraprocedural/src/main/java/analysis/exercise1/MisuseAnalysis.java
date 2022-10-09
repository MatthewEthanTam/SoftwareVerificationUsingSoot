package analysis.exercise1;

import analysis.AbstractAnalysis;
import analysis.VulnerabilityReporter;
import soot.*;
import soot.jimple.*;

public class MisuseAnalysis extends AbstractAnalysis{
	public MisuseAnalysis(Body body, VulnerabilityReporter reporter) {
		super(body, reporter);
	}
	
	@Override
	protected void flowThrough(Unit unit) {
		String cypherClass = "javax.crypto.Cipher";
		String getInstanceCall = "getInstance";
		String correctConvention = "AES/GCM/PKCS5Padding";
		/**
		 *  Since Stmt and Unit are the same and
		 *  we are only interested in the `Cipher.getInstance()`,
		 *  we can cast the Unit to a Stmt because Stmt can get and
		 *  see if an expression is created such as `Cipher.getInstance()`
		 */
		
		Stmt st = (Stmt) unit; 		

		/**
		 *  We then want to check if the statements in the code contain that invokes
		 *  an expression. such as the Cipher aesChipher; method.
		 * 
		 *  Thus if the statement does contain an expression we retrieve the expression, method and the class
		 *  of the method and check if the class name is equal to `javax.crypto.Cipher` which is the cypher class 
		 * 	and the method name is equal to `getInstance` which is the method we are looking for.
		 * 
		 * 	Then we check if the expressions first argument is a String but since it is 
		 *  in Soot we check the StringConstant class using InstanceOf.
		 * 
		 *  Finally we check if the expression's first parameter is equal to `AES/GCM/PKCS5Padding`
		 *  if not then it throws an error.
		 * 
		 *  */	
		 
		if (st.containsInvokeExpr()) {
			InvokeExpr exprSoot = st.getInvokeExpr(); 
			SootMethod methodSoot =  exprSoot.getMethod(); 
			SootClass methodClassSoot = exprSoot.getMethod().getDeclaringClass(); 
			String methodName = methodSoot.getName();
			String methodClassName = methodClassSoot.getName();

			if (methodName.equals(getInstanceCall) && // Check if the method name is equal to `getInstance`
				methodClassName.equals(cypherClass) && // Check if the class name is equal to `javax.crypto.Cipher`
				exprSoot.getArg(0) instanceof StringConstant &&  // Check if the first argument is a String
				!((StringConstant) exprSoot.getArg(0)).value.equals(correctConvention)) // Check if the first parameter of expression is equal to `AES/GCM/PKCS5Padding`
				{ 
					reporter.reportVulnerability(method.getSignature(), unit);
				}
			}
		}
	}
