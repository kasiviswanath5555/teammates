### TEAM - MAVERICKS - Code Analysis for Software Security Engineering

### A) Code Review Strategy 
   We did a manual code review for the Critical Claims as well as used the automated tool “Find Bugs” for automated scanning of TeamMates. Before running the automation tool, we had filtered the tool to check for Security and Malicious Code vulnerabilities related issues.
   
### B) Manual code review of critical security functions

+ A manual code review was done on the assurance claim “Feedback session module of TeamMates is acceptably secure to HTTP response splitting Weaknesses”, to verify if there were strategies implemented in the code to prevent the injection of malicious special characters i.e. CR and LF through HTTP headers during the submission of feedback session form and before the storage of the form attributes in the TeamMates Storage entities.
  We could see the Feedback session form filled by external interactors in TeamMates i.e. students or Instructors are properly validated and sanitized by the Sanitization Helper Class to neutralize any malicious java scripts. TeamMates basically uses a whitelist of acceptable inputs that strictly conform to the specifications. 
 TeamMates also uses a FieldValidator class to restrict the length of each of the feedback session attributes to mitigate the attacks.

+ As part of the assurance claim “Login Module of TeamMates is acceptably secure to brute force attack”, a manual code review was done to verify if there were strategies implemented to ensure proper access control rights to prevent unauthorized access to exploit the TeamMates Login Module through brute force attack. 
  A manual testing was done on the TeamMates instance in the dev server to check the secure practices are enforced. TeamMates enforces secure access control rights during user Login by using a “GateKeeper.java” class which is accessed by the LoginServlet to check the access control. The GateKeeper class checks if the user account details are present in the GAE datastore. After which the privileges are assigned to the user based on its role. This prevents unauthorized users to access and exploit the teammates modules. 
  TeamMates also uses records all the user activities in logs which in turn warns the administrator of possible attack.

+ As per the assurance claim “Courses Module of TeamMates is acceptably secure to exploitable injection weaknesses”, a manual code review was done on the Teammates and found that, TeamMates restricts sending sensitive data in a JSON array by enforcing secure coding standards. It also uses strong sanitization practices before storing course details in the datastore. All the inputs fields such as CourseId, CourseName are sanitized before storing into the datastore.
  
+ Manual code review was performed for the claim “Teammates acceptable preserves the privacy of user feedbacks” to verify whether the standard privacy policy practices were followed to ensure user feedback is anonymous and no information regarding username is exposed. Further, manual code review was performed to check if role based login was implemented. In this regards, manual testing was done to ensure that no user name is displayed after giving feedback. Teammates uses role based login to ensure privacy and follows privacy follows based on FedRAMP ATO standards.  Sessions are maintained to store the current details and are deleted once session is closed or expired. On observing a sample feedback JSON output file, the information contains no username.  On providing feedback, the user name is not displayed and anonymously the feedback is provided.

+ For the assurance claim “Teammates is acceptably secure to exploitable XSS weakness”, a manual code review was done to verify whether TeamMates enforces strong sanitization practices to avoid the web sessions from vulnerable CSRF attack.
 As part of manual code review, we found that in TeamMates, the Http responses for the FeedbackSession Module are properly sanitized in TeamMates using the “SanitizationHelper” class. This class contains methods to sanitize user provided parameters so that they conform to given data format and possible threats can be removed first as well as methods to revert sanitized text back to its previous unsanitized state. The class CryptoHelper Ensures the encryption policies required for the feedback session.

### C) Automated Test Report from Find Bugs 
+ An automated test scan was executed on TeamMates in eclipse using Find Bugs. Few settings were done to include only those vulnerabilities which were related to Malicious Code and Security. 

+ The Scan resulted in a total of 48 Scary bugs and 2 troubling bugs.The full report link is provided below
https://raw.githubusercontent.com/nbiswal/teammates/master/Findbugs%20TeamMates%20Report.xml

+ Screenshot of the report from the bug explorer
<img src="https://github.com/kasiviswanath5555/teammates/blob/master/screenshot1.jpg" width="600">

### D) Summary of Key Findings:

+ As part of the claims we did a CWE mapping and checked the respective CWE IDs for the possible mitigation steps. After which we checked TeamMates to see if these mitigation strategies are implemented in the code in addition to those identified as part of the assurance claims and misuse case threat models.

+ For the assurance claim “Feedback session module of TeamMates is acceptably secure to HTTP response splitting Weaknesses”. 
  + #### CWE Mapping – CWE 113 
    + As per CWE 113 the possible mitigation steps for HTTP Response Splitting are Input Validation and Output Encoding. As per the code review we could see TeamMates has enforced proper input validations i.e. by neutralizing the malicious characters in java scripts using sanitization methods and using proper encoding practices for HTML. TeamMates implements URI encoding strategies which prevents an attacker to launch an injection attack and mitigates the possible tampering of data by an attacker in the logic API, Storage API and storage entities database as per CAPEC 34.
  
  + #### Automated code Scanning
    +  Automated code Scanning through Find bugs highlighted some security vulnerabilities i.e. “Unvalidated_Redirect” related to the redirect page in Controller Servlet. But TeamMates uses the redirect URL to redirect unauthorized users to an error page. Also “Unvalidated_Redirect” was flagged for the home page URL of the TeamMates users but TeamMates enforces secure practices to enforce secure sanitization and encoding practices for HTML.
 
+ For the assurance claim “Login Module of TeamMates is acceptably secure to brute force attack”.
  + #### CWE Mapping – CWE 257, CWE 307, CWE 287, CWE 328, CWE 334, CWE 521, CWE 640, CWE 549, CWE 804
    + As per most of the CWE ID’s the possible mitigation steps for preventing brute force attack are mostly the same i.e. Use strong, non-reversible encryption to protect stored passwords, Disconnecting the user after a small number of failed login attempts. As per the manual Code review TeamMates uses a secure authentication mechanism by using the Gatekeeper class. As per the attack pattern CAPEC 49 we tried to brute force the system by using an existing google login id. We could see Google App Engine not only enforces strong password practices but also enforces secure practices like CAPTCHA after a certain number of failed login attempts. Google Server also restricts the use of verbose error messages to mitigate the attacks. Even if we login using a google Id and password TeamMates doesn’t allow to access any of its modules if the user is not registered.  
  
  + #### Automated code Scanning 
    + Automated code Scanning through Find bugs highlighted some security vulnerabilities i.e. Potential CRLF injection for logs which can impact the log activities. TeamMates enforces secure input data validation to prevent the exploitation of logs. Also the automated code scanning refers to the below line of code in the StringHelper class as insecure 
    Cipher c = Cipher.getInstance ("AES/ECB/PKCS5Padding"); -->(used for encrypting the userid's) but TeamMates already enforces secure practices like using HMAC-MD5 algorithm which is first applied on the data(cryptoHelper class)and then the cryptographic functions are applied.
    
 + For the Assurance claim “Courses Module of TeamMates is acceptably secure to exploitable injection weaknesses”.
   + #### CWE Mapping – CWE 454
     + As per CWE 454 the possible mitigation steps for exploitable injection weakness before storing into datastore should be reluctant to trust variables which are initialized outside boundaries. As per the code review we could see TeamMates has enforced sending secure data in a JSON array and uses a strong sanitization practices for the details in the datastore.
     
 + For the assurance claim “Teammates acceptable preserves the privacy of user feedbacks”.
   + #### CWE Mapping - CWE-359, CWE-200, CWE-274, CWE-280, CWE-271
     + Based on the CWE ID’s, one possible introduction of this weaknesses might be caused during the implementation of architectural security tactic.  Possible mitigations include in the architecture and design phase by managing setting, management and handling of privileges. Explicitly the trust zones should be managed in the software. Another possible mitigation is to follow the principle of separation of privilege.
    
 + For the assurance claim “Teammates is acceptably secure to exploitable XSS weakness”.
   + #### CWE Mapping: CWE 79, CWE 80, CWE 85, CWE 87, CWE 712, CWE 725, CWE 809, CWE 928
     + Most of the above CWE ID’s mentioned that the possible mitigation steps for avoiding exploitable XSS weakness are by checking each input parameter against a rigorous positive specification (i.e. Input Validation) and by Output Encoding that can be handled by the downstream component that is reading the output.
   
### E) Issue Request Links
+ https://github.com/TEAMMATES/teammates/issues/8178
+ https://github.com/TEAMMATES/teammates/issues/8183
