control 'SV-271307' do
  title 'If DBMS authentication using passwords is employed, SQL Server must enforce the DOD standards for password complexity and lifetime.'
  desc 'Windows Authentication is the default authentication mode and is much more secure than SQL Server Authentication. Windows Authentication uses Kerberos security protocol, provides password policy enforcement regarding complexity validation for strong passwords, provides support for account lockout, and supports password expiration. A connection made using Windows Authentication is sometimes called a trusted connection, because SQL Server trusts the credentials provided by Windows.

By using Windows Authentication, Windows groups can be created at the domain level, and a login can be created on SQL Server for the entire group. Managing access at the domain level can simplify account administration.

OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native SQL Server authentication may be used only when circumstances make it unavoidable and must be documented and authorizing official (AO)-approved. 
 
The DOD standard for authentication is DOD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate and requires AO approval. 
 
In such cases, the DOD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For other DBMSs, the rules must be enforced using available configuration parameters or custom code.'
  desc 'check', %q(Check for use of SQL Authentication:

SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
WHEN 1 THEN 'Windows Authentication' WHEN 0 THEN 'SQL Authentication' 
END as [Authentication Mode]

If the returned value in the "Authentication Mode" column is "Windows Authentication", this is not a finding.  

SQL Server should be configured to inherit password complexity and password lifetime rules from the operating system. Review the SQL Server Instance to ensure logons are created with respect to the complexity settings and password lifetime rules by running the following statement:

SELECT
[name],
is_expiration_checked,
is_policy_checked,*
FROM
sys.sql_logins
WHERE
is_disabled = 0
AND name NOT IN ('##MS_PolicyTsqlExecutionLogin##','##MS_PolicyEventProcessingLogin##')
AND sid <> 1
 
If any account does not have both "is_expiration_checked" and "is_policy_checked" equal to "1", this is a finding.)
  desc 'fix', "Ensure check of policy and expiration are enforced when SQL logins are created. 

Use the command below to set CHECK_EXPIRATION and CHECK_POLICY  for any login found to be noncompliant:

ALTER LOGIN [LoginnameHere] WITH CHECK_EXPIRATION=ON;
ALTER LOGIN [LoginNameHere] WITH CHECK_POLICY=ON;

New SQL authenticated logins must be created with CHECK_EXPIRATION and CHECK_POLICY set to ON.

CREATE LOGIN [LoginNameHere]  WITH PASSWORD = 'ComplexPasswordHere', CHECK_EXPIRATION = ON, CHECK_POLICY = ON;"
  impact 0.7
  tag check_id: 'C-75350r1109240_chk'
  tag severity: 'high'
  tag gid: 'V-271307'
  tag rid: 'SV-271307r1109241_rule'
  tag stig_id: 'SQLI-22-007900'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-75257r1109010_fix'
  tag 'documentable'
  tag legacy: ['SV-93897', 'V-79191']
  tag cci: ['CCI-000192', 'CCI-004066', 'CCI-003627']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (h)', 'AC-2 (3) (a)']
end
