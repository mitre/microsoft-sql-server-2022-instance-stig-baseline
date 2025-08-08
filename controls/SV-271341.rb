control 'SV-271341' do
  title 'SQL Server must prevent nonprivileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 
 
System documentation should include a definition of the functionality considered privileged. 
 
Depending on circumstances, privileged functions can include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Nonprivileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from nonprivileged users. 
 
A privileged function in SQL Server/database context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:  
CREATE 
ALTER 
DROP 
GRANT 
REVOKE 
DENY 
 
There may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. Possible examples include: 
TRUNCATE TABLE; 
DELETE, or 
DELETE affecting more than n rows, for some n, or 
DELETE without a WHERE clause; 
 
UPDATE or 
UPDATE affecting more than n rows, for some n, or 
UPDATE without a WHERE clause; 
 
Any SELECT, INSERT, UPDATE, or DELETE to an application-defined security table executed by other than a security principal. 
 
Depending on the capabilities of SQL Server and the design of the database and associated applications, the prevention of unauthorized use of privileged functions may be achieved by means of DBMS security features, database triggers, other mechanisms, or a combination of these.'
  desc 'check', "Review server-level securables and built-in role membership to ensure only authorized users have privileged access and the ability to create server-level objects and grant permissions to themselves or others. 
 
Review the system documentation to determine the required levels of protection for DBMS server securables by type of login. 
 
Review the permissions in place on the server. If the actual permissions do not match the documented requirements, this is a finding. 
 
Get all permission assignments to logins and roles: 
 
SELECT DISTINCT 
    CASE 
        WHEN SP.class_desc IS NOT NULL THEN 
            CASE 
                WHEN SP.class_desc = 'SERVER' AND S.is_linked = 0 THEN 'SERVER' 
                WHEN SP.class_desc = 'SERVER' AND S.is_linked = 1 THEN 'SERVER (linked)' 
                ELSE SP.class_desc 
            END 
        WHEN E.name IS NOT NULL THEN 'ENDPOINT' 
        WHEN S.name IS NOT NULL AND S.is_linked = 0 THEN 'SERVER' 
        WHEN S.name IS NOT NULL AND S.is_linked = 1 THEN 'SERVER (linked)' 
        WHEN P.name IS NOT NULL THEN 'SERVER_PRINCIPAL' 
        ELSE '???' 
    END                    AS [Securable Class], 
    CASE 
        WHEN E.name IS NOT NULL THEN E.name 
        WHEN S.name IS NOT NULL THEN S.name 
        WHEN P.name IS NOT NULL THEN P.name 
        ELSE '???' 
    END                    AS [Securable], 
    P1.name                AS [Grantee], 
    P1.type_desc           AS [Grantee Type], 
    sp.permission_name     AS [Permission], 
    sp.state_desc          AS [State], 
    P2.name                AS [Grantor], 
    P2.type_desc           AS [Grantor Type] 
FROM 
    sys.server_permissions SP 
    INNER JOIN sys.server_principals P1 
        ON P1.principal_id = SP.grantee_principal_id 
    INNER JOIN sys.server_principals P2 
        ON P2.principal_id = SP.grantor_principal_id 
 
    FULL OUTER JOIN sys.servers S 
        ON  SP.class_desc = 'SERVER' 
        AND S.server_id = SP.major_id 
 
    FULL OUTER JOIN sys.endpoints E 
        ON  SP.class_desc = 'ENDPOINT' 
        AND E.endpoint_id = SP.major_id 
 
    FULL OUTER JOIN sys.server_principals P 
        ON  SP.class_desc = 'SERVER_PRINCIPAL'        
        AND P.principal_id = SP.major_id 
 
Get all server role memberships: 
 
SELECT 
    R.name    AS [Role], 
    M.name    AS [Member] 
FROM 
    sys.server_role_members X 
    INNER JOIN sys.server_principals R ON R.principal_id = X.role_principal_id 
    INNER JOIN sys.server_principals M ON M.principal_id = X.member_principal_id 
 
The CONTROL SERVER permission is similar but not identical to the sysadmin fixed server role. Permissions do not imply role memberships, and role memberships do not grant permissions (e.g., CONTROL SERVER does not imply membership in the sysadmin fixed server role). 
 
Ensure only the documented and approved logins have privileged functions in SQL Server. 
 
If the current configuration does not match the documented baseline, this is a finding."
  desc 'fix', 'Restrict the granting of permissions to server-level securables to only those authorized, most notably: members of sysadmin and securityadmin built-in instance-level roles, CONTROL SERVER permission, and use of the GRANT with GRANT permission.'
  impact 0.5
  tag check_id: 'C-75384r1109251_chk'
  tag severity: 'medium'
  tag gid: 'V-271341'
  tag rid: 'SV-271341r1111081_rule'
  tag stig_id: 'SQLI-22-010400'
  tag gtitle: 'SRG-APP-000340-DB-000304'
  tag fix_id: 'F-75291r1109252_fix'
  tag 'documentable'
  tag legacy: ['SV-82375', 'V-67885', 'SV-93925', 'V-79219']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  sql = mssql_session(user: input('user'),
                      password: input('password'),
                      host: input('host'),
                      instance: input('instance'),
                      port: input('port'))
  permissions = sql.query("SELECT Grantee as 'result' FROM STIG.database_permissions WHERE Permission LIKE '%CREATE%' OR Permission LIKE '%ALTER%'").column('result')

  if  permissions.empty?
    impact 0.0
    desc 'There are no sql privileged users, control not applicable'

    describe 'There are no sql privileged users, control not applicable' do
      skip 'There are no sql privileged users, control not applicable'
    end
  else
    permissions.each do |perms|
      a = perms.strip
      describe "sql privileged users: #{a}" do
        subject { a }
        it { should be_in input('allowed_users') }
      end
    end

  end
end
