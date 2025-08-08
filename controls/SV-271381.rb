control 'SV-271381' do
  title 'SQL Server must generate audit records for all direct access to the database(s).'
  desc 'In this context, direct access is any query, command, or call to SQL Server that comes from any source other than the application(s) that it supports. Examples would be the command line or a database management utility program. The intent is to capture all activity from administrative and nonstandard sources.'
  desc 'check', 'Determine whether any Server Audits are configured to filter records. From SQL Server Management Studio, execute the following query:
SELECT name AS AuditName, predicate AS AuditFilter
FROM sys.server_audits
WHERE predicate IS NOT NULL

If any audits are returned, review the associated filters. If any direct access to the database(s) is being excluded, this is a finding.'
  desc 'fix', 'Check the system documentation for required SQL Server Audits. Remove any Audit filters that exclude or reduce required auditing. Update filters to ensure direct access is not excluded.'
  impact 0.5
  tag check_id: 'C-75424r1111094_chk'
  tag severity: 'medium'
  tag gid: 'V-271381'
  tag rid: 'SV-271381r1111095_rule'
  tag stig_id: 'SQLI-22-015500'
  tag gtitle: 'SRG-APP-000508-DB-000358'
  tag fix_id: 'F-75331r1109049_fix'
  tag 'documentable'
  tag legacy: ['SV-94009', 'V-79303']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
