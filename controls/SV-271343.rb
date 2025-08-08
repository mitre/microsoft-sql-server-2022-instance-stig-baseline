control 'SV-271343' do
  title 'SQL Server must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to SQL Server on its own server will not be an issue. However, space will still be required on the server for SQL Server Audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result. 
 
If support personnel are not notified immediately upon storage volume utilization reaching 75 percent, they are unable to plan for storage capacity expansion. 
 
The appropriate support staff include, at a minimum, the information system security officer (ISSO), the database administrator (DBA), and system administrator (SA). 
 
Monitoring of free space can be accomplished using Microsoft System Center or a third-party monitoring tool.'
  desc 'check', 'If the database is setup to write audit logs using APPLICATION or SECURITY event logs rather than writing to a file, this is Not Applicable.

Check the server documentation for the SQL Audit file size configurations. Locate the Audit file path and drive. 
 
SELECT max_file_size, max_rollover_files, log_file_path AS "Audit Path"  
FROM sys.server_file_audits 
 
Calculate the space needed as the maximum file size and number of files from the SQL Audit File properties. 
 
If the calculated product of the "max_file_size" times the "max_rollover_files" exceeds the size of the storage location, this is a finding; 

OR if "max_file_size" is set to "0" (Unlimited), this is a finding;

OR if "max_rollover_files" are set to "0" (None) or "2147483647" (Unlimited), this is a finding.'
  desc 'fix', 'Review the SQL Audit file location; ensure the destination has enough space available to accommodate the maximum total size of all files that could be written. 
 
Configure the maximum number of audit log files that are to be generated, staying within the number of logs the system was sized to support. 
 
Update the "max_files" or "max_rollover_files" parameter of the audits to ensure the correct number of files is defined.

If writing to application event logs or security logs, space considerations are covered in the Windows Server STIGs. Be sure to reference these depending on the OS in use.'
  impact 0.5
  tag check_id: 'C-75386r1108643_chk'
  tag severity: 'medium'
  tag gid: 'V-271343'
  tag rid: 'SV-271343r1108645_rule'
  tag stig_id: 'SQLI-22-010900'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-75293r1108644_fix'
  tag 'documentable'
  tag legacy: ['V-67891', 'SV-82381', 'SV-93933', 'V-79227']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

  describe "SQL Server must allocate audit record storage capacity in accordance
  with organization-defined audit record storage requirements." do
    skip 'This control is manual'
  end
end
