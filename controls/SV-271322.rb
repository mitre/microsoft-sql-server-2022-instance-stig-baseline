control 'SV-271322' do
  title 'The Master Key must be backed up and stored in a secure location that is not on the SQL Server.'
  desc 'Backup and recovery of the Master Key may be critical to the complete recovery of the database. Not having this key can lead to loss of data during recovery.'
  desc 'check', 'If the application owner and authorizing official have determined that encryption of data at rest is not required, this is not a finding. 
 
Review procedures for and evidence of backup of the Master Key in the System Security Plan. 
 
If the procedures or evidence does not exist, this is a finding. 
 
If the procedures do not indicate that a backup of the Master Key is stored in a secure location that is not on the SQL Server, this is a finding.

If procedures do not indicate access restrictions to the Master Key backup, this is a finding.'
  desc 'fix', "Document and implement procedures to safely back up and store the Master Key in a secure location that is not on the SQL Server. Include in the procedures methods to establish evidence of backup and storage, and careful, restricted access and restoration of the Master Key.

BACKUP MASTER KEY TO FILE = 'path_to_file'  
ENCRYPTION BY PASSWORD = 'password';  
 
As this requires a password, take care to ensure it is not exposed to unauthorized persons or stored as plain text."
  impact 0.7
  tag check_id: 'C-75365r1108580_chk'
  tag severity: 'high'
  tag gid: 'V-271322'
  tag rid: 'SV-271322r1108582_rule'
  tag stig_id: 'SQLI-22-009700'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-75272r1108581_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
