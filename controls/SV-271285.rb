control 'SV-271285' do
  title 'SQL Server must limit privileges to change software modules and links to software external to SQL Server.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications. 
 
Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', %q(Review Server documentation to determine the authorized owner and users or groups with modify rights for this SQL instance's binary files. Additionally check the owner and users or groups with modify rights for shared software library paths on disk. 
 
If any unauthorized users are granted modify rights or the owner is incorrect, this is a finding. 

To determine the location for these instance-specific binaries:

1. Launch SQL Server Management Studio (SSMS). 
2. Connect to the instance to be reviewed. 
3. Right-click server name in "Object Explorer".
4. Click "Facets".
5. Select the "Server" facet. 
6. Record the value for the "RootDirectory" facet property. 
7. Navigate to the folder above and review the "Binn" subdirectory.

TIP: Use the Get-FileHash cmdlet shipped with PowerShell 5.0 to get the SHA-2 hash of one or more files.)
  desc 'fix', 'Change the ownership of all shared software libraries on disk to the authorized account. Remove any modify permissions granted to unauthorized users or groups.'
  impact 0.5
  tag check_id: 'C-75328r1109235_chk'
  tag severity: 'medium'
  tag gid: 'V-271285'
  tag rid: 'SV-271285r1109236_rule'
  tag stig_id: 'SQLI-22-006500'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-75235r1108470_fix'
  tag 'documentable'
  tag legacy: ['SV-93869', 'V-79163']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
