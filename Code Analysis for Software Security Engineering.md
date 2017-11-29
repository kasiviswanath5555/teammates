### TEAM - MAVERICKS - Code Analysis for Software Security Engineering

### A) Code Review Strategy 
   We did a manual code review for the Critical Claims as well as used the automated tool “Find Bugs” for automated scanning of TeamMates. Before running the automation tool, we had filtered the tool to check for Security and Malicious Code vulnerabilities related issues.

   Based on our top 5 critical assurance claims, we did a thorough manual review of all the modules that may be impacted as part of these claims. The basis of the review is as mentioned below:
### B) Manual code review of critical security functions
+ A manual code review was done on the assurance claim “Feedback session module of TeamMates is acceptably secure to HTTP response splitting Weaknesses”, a code review was done to verify if there were strategies implemented in the code to prevent the injection of malicious special characters i.e. CR and LF through HTTP headers during the submission of feedback session form and before the storage of the form attributes in the TeamMates Storage entities. 
+ As part of the assurance claim “Login Module of TeamMates is acceptably secure to brute force attack”, a manual code review was done to verify if there were strategies implemented to ensure proper access control rights to prevent unauthorized access to exploit the TeamMates Login Module through brute force attack. A manual testing was done on the TeamMates instance in the dev server to check the secure practices that are enforced.
### C) Automated Test Report from Find Bugs 
An automated test scan was executed on TeamMates in eclipse using Find Bugs. Few settings were done to include only those vulnerabilities which were related to Malicious Code and Security. The Scan resulted in a total of 48 Scary bugs and 2 troubling bugs.
https://raw.githubusercontent.com/nbiswal/teammates/master/Findbugs%20TeamMates%20Report.xml

<img src="https://github.com/kasiviswanath5555/teammates/blob/master/screenshot1.jpg" width="600">

### D) Summary of Key Findings:

As part of the claims we did a CWE mapping and checked the respective CWE IDs for the possible mitigation steps. After which we checked TeamMates to see if these mitigation strategies are implemented in the code in addition to those identified as part of the assurance claims and misuse case threat models.

+ For the assurance claim “Feedback session module of TeamMates is acceptably secure to HTTP response splitting Weaknesses”. 
  + #### CWE Mapping – CWE 113 
    + As per CWE 113 the possible mitigation steps for HTTP Response Splitting are Input Validation and Output Encoding. So, the code was reviewed to check if proper input validations and output encoding are done. 
  + #### Manual Code Review 
    + In TeamMates, the Feedback session form filled by external interactors i.e. students or Instructors are properly validated and sanitized by the Sanitization Helper Class to neutralize any malicious java scripts. TeamMates basically uses a whitelist of acceptable inputs that strictly conform to the specifications. Apart from that TeamMates implements URI encoding strategies which prevents an attacker to launch an injection attack and mitigates the possible tampering of data by an attacker in the logic API, Storage API and storage entities database as per CAPEC 34. TeamMates also uses a FieldValidator class to restrict the length of each of the feedback session attributes to mitigate the attacks.
  + #### Automated code Scanning
    +  Automated code Scanning through Find bugs highlighted some security vulnerabilities i.e. “Unvalidated_Redirect” related to the redirect page in Controller Servlet. But TeamMates uses the redirect URL to redirect unauthorized users to an error page. Also “Unvalidated_Redirect” was flagged for the home page URL of the TeamMates users but TeamMates enforces secure practices to enforce secure sanitization and encoding practices for HTML.
 
+ For the assurance claim “Login Module of TeamMates is acceptably secure to brute force attack”.
  + #### CWE Mapping – CWE 257, CWE 307, CWE 287, CWE 328, CWE 334, CWE 521, CWE 640, CWE 549, CWE 804
    + As per most of the CWE ID’s the possible mitigation steps for preventing brute force attack are mostly the same i.e. Use strong, non-reversible encryption to protect stored passwords, Disconnecting the user after a small number of failed login attempts.
  + #### Manual Code Review 
    + TeamMates uses a third-party server known as Google App Engine TeamMates enforces secure access control rights during user Login by using a “GateKeeper.java” class which is accessed by the LoginServlet to check the access control. The GateKeeper class checks if the user account details are present in the GAE datastore. After which the privileges are assigned to the user based on its role. This prevents unauthorized users to access and exploit the teammates modules. TeamMates also uses records all the user activities in logs which in turn warns the administrator of possible attack.
  + #### Manual Testing 
    + As per the attack pattern CAPEC 49 we tried to brute force the system by using an existing google login id. We could see Google App Engine not only enforces strong password practices but also enforces secure practices like CAPTCHA after a certain number of failed login attempts. Google Server also restricts the use of verbose error messages to mitigate the attacks. Even if we login using a google Id and password TeamMates doesn’t allow to access any of its modules if the user is not registered.  
  + #### Automated code Scanning 
    + Automated code Scanning through Find bugs highlighted some security vulnerabilities i.e. Potential CRLF injection for logs which can impact the log activities. TeamMates enforces secure input data validation to prevent the exploitation of logs.
### E) Issue Request Links
+ https://github.com/TEAMMATES/teammates/issues/8178
+ https://github.com/TEAMMATES/teammates/issues/8183
