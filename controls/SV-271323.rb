control 'SV-271323' do
  title 'The Service Master Key must be backed up and stored in a secure location that is not on the SQL Server.'
  desc 'Backup and recovery of the Service Master Key may be critical to the complete recovery of the database. Creating this backup should be one of the first administrative actions performed on the server. Not having this key can lead to loss of data during recovery.'
  desc 'check', 'Review procedures for and evidence of backup of the Server Service Master Key in the System Security Plan. 
 
If the procedures or evidence does not exist, this is a finding.
 
If the procedures do not indicate that a backup of the Service Master Key is stored in a secure location that is not on the SQL Server, this is a finding. 

If procedures do not indicate access restrictions to the Service Master Key backup, this is a finding.'
  desc 'fix', "Document and implement procedures to safely back up and store the Service Master Key in a secure location that is not on the SQL Server. In the procedures, include methods to establish evidence of backup and storage, and careful, restricted access and restoration of the Service Master Key.
 
BACKUP SERVICE MASTER KEY TO FILE = 'path_to_file'  
ENCRYPTION BY PASSWORD = 'password';  
 
As this requires a password, take care to ensure it is not exposed to unauthorized persons or stored as plain text."
  impact 0.7
  tag check_id: 'C-75366r1108583_chk'
  tag severity: 'high'
  tag gid: 'V-271323'
  tag rid: 'SV-271323r1108585_rule'
  tag stig_id: 'SQLI-22-009600'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-75273r1108584_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
