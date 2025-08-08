control 'SV-271263' do
  title 'SQL Server must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.'
  desc 'Database management includes the ability to control the number of users and user sessions using a DBMS. Unlimited concurrent connections to the DBMS could allow a successful denial-of-service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts.

The capability to limit the number of concurrent sessions per user must be configured in or added to the DBMS (for example, by use of a logon trigger), when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to the DBMS by other means.

The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, two might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.

Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.'
  desc 'check', "Review the system documentation to determine whether any concurrent session limits have been defined. If it does not, assume a limit of 10 for database administrators and two for all other users. 
 
If a mechanism other than a logon trigger is used, verify its correct operation by the appropriate means. If it does not work correctly, this is a finding.

Due to excessive CPU consumption when using a logon trigger, an alternative method of limiting concurrent sessions is setting the max connection limit within SQL Server to an appropriate value. This serves to block a distributed denial-of-service (DDOS) attack by limiting the attacker's connections while allowing a database administrator to still force a SQL connection.

In SQL Server Management Studio's Object Explorer tree, right-click on the Server Name >> Properties >> Connections Tab.

OR

Run the query:
EXEC sys.sp_configure N'user connections'

If the max connection limit is set to 0 (unlimited) or does not match the documented value, this is a finding.
 
Otherwise, determine if a logon trigger exists:  
 
In SQL Server Management Studio's Object Explorer tree, expand [SQL Server Instance] >> Server Objects >> Triggers.
 
OR 
 
Run the query:  
SELECT name FROM master.sys.server_triggers;  
 
If no triggers are listed, this is a finding. 
 
If triggers are listed, identify the trigger(s) limiting the number of concurrent sessions per user. If none are found, this is a finding. If they are present but disabled, this is a finding. 
 
Examine the trigger source code for logical correctness and for compliance with the documented limit(s). If errors or variances exist, this is a finding.
 
Verify that the system does execute the trigger(s) each time a user session is established. If it does not operate correctly for all types of user, this is a finding."
  desc 'fix', "If a trigger consumes too much CPU, an example alternative method for limiting the concurrent users is setting the max connection limit on SQL Server.

In SQL Server Management Studio's Object Explorer tree, right-click on the Server Name >> Properties >> Connections Tab >> Set the Maximum Number of Concurrent Connections to a value other than 0 (0 = unlimited), and document it.

OR

Run the query:

EXEC sys.sp_configure N'user connections','5000' /* this is an example max limit */
GO
RECONFIGURE WITH OVERRIDE
GO

Restart SQL Server for the setting to take effect.

Reference: https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-user-connections-server-configuration-option?

Otherwise, establish the limit(s) appropriate to the type(s) of user account accessing the SQL Server instance, and record them in the system documentation. Implement one or more logon triggers to enforce the limit(s), without exposing the dynamic management views to general users. 

Example script:
 
CREATE TRIGGER SQL_STIG_Connection_Limit 
ON ALL SERVER WITH EXECUTE AS 'renamed_sa' /*Make sure to use the renamed SA account here*/ 
FOR LOGON 
AS 
BEGIN 
If (Select COUNT(1) from sys.dm_exec_sessions WHERE is_user_process = 1 AND original_login_name = ORIGINAL_LOGIN() ) > 
  (CASE ORIGINAL_LOGIN()
              WHEN 'domain/ima.dba' THEN 150    /*this is a busy DBA's domain account */
              WHEN 'application1_login' THEN 6  /* this is a SQL login for an application */
              WHEN 'application2_login' THEN 20 /* this is a SQL login for another application */
              …
              ELSE 1 /* All unspecified users are restricted to a single login */
  END)
              BEGIN 
                             PRINT 'The login [' + ORIGINAL_LOGIN() + '] has exceeded its concurrent session limit.' 
                             ROLLBACK; 
              END
END; 
  
Reference: https://msdn.microsoft.com/en-us/library/ms189799.aspx"
  impact 0.5
  tag check_id: 'C-75306r1108403_chk'
  tag severity: 'medium'
  tag gid: 'V-271263'
  tag rid: 'SV-271263r1108405_rule'
  tag stig_id: 'SQLI-22-003600'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-75213r1108404_fix'
  tag 'documentable'
  tag legacy: ['SV-93825', 'V-79119']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
