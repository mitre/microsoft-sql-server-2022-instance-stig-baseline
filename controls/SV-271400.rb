control 'SV-271400' do
  title 'SQL Server must, for password-based authentication, require immediate selection of a new password upon account recovery.'
  desc 'Password-based authentication applies to passwords regardless of whether they are used in single-factor or multifactor authentication. Long passwords or passphrases are preferable over shorter passwords. Enforced composition rules provide marginal security benefits while decreasing usability. However, organizations may choose to establish certain rules for password generation (e.g., minimum character length for long passwords) under certain circumstances and can enforce this requirement in IA-5(1)(h). Account recovery can occur, for example, in situations when a password is forgotten. Cryptographically protected passwords include salted one-way cryptographic hashes of passwords. The list of commonly used, compromised, or expected passwords includes passwords obtained from previous breach corpuses, dictionary words, and repetitive or sequential characters. The list includes context-specific words, such as the name of the service, username, and derivatives thereof.'
  desc 'check', %q(Check for use of SQL Server Authentication:
SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly') WHEN 1 THEN 'Windows Authentication' WHEN 0 THEN 'SQL Server Authentication' END as [Authentication Mode]

If the returned value in the "Authentication Mode" column is "Windows Authentication", this is not a finding.

If the returned value is not "Windows Authentication", verify SQL Server is configured to require immediate selection of a new password upon account recovery.

All scripts, functions, triggers, and stored procedures that are used to create a user or reset a user's password should include a line similar to the following password_option:
MUST_CHANGE

Example:
CREATE LOGIN STIG_test WITH PASSWORD ='Password' MUST_CHANGE, 
     CHECK_EXPIRATION = ON,
     CHECK_POLICY = ON;

If they do not, this is a finding.

If SQL Server is not configured to require immediate selection of a new password upon account recovery, this is a finding.)
  desc 'fix', "Configure the DBMS to require immediate selection of a new password upon account recovery.

Ensure that all scripts, functions, triggers, and stored procedures that are used to create a user or reset a user's password include a line similar to the following password_option:
MUST_CHANGE

If MUST_CHANGE is specified, CHECK_EXPIRATION and CHECK_POLICY must be set to ON. Otherwise, the statement will fail.

More information can be found at https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql?view=sql-server-ver16."
  impact 0.5
  tag check_id: 'C-75443r1111149_chk'
  tag severity: 'medium'
  tag gid: 'V-271400'
  tag rid: 'SV-271400r1111151_rule'
  tag stig_id: 'SQLI-22-019500'
  tag gtitle: 'SRG-APP-000855-DB-000240'
  tag fix_id: 'F-75350r1111150_fix'
  tag 'documentable'
  tag cci: ['CCI-004063']
  tag nist: ['IA-5 (1) (e)']
end
