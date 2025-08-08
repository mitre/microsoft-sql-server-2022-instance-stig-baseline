control 'SV-274452' do
  title 'The SQL Server User Options feature must be disabled unless specifically required and approved.'
  desc %q(SQL Server is capable of providing a wide range of features and services. Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect system security.

The "user options" option specifies global defaults for all users. A list of default query processing options is established for the duration of a user's work session. The "user options" option enables changing the default values of the SET options (if the server's default settings are not appropriate).)
  desc 'check', %q(To determine if "User Options" option is enabled, execute the following query:

EXEC SP_CONFIGURE 'show advanced options', '1'; 
RECONFIGURE WITH OVERRIDE; 
EXEC SP_CONFIGURE 'user options'; 

If the value of "config_value" is "0", this is not a finding. 

If the value of "config_value" is "1", review the system documentation to determine whether the use of "user options" is required and authorized. If it is not authorized, this is a finding.)
  desc 'fix', %q(Disable use of or remove any external application executable object definitions that are not authorized. To disable the use of the "User Options" option, from the query prompt:
sp_configure 'show advanced options', 1;  
GO  
RECONFIGURE;  
GO  
sp_configure 'user options', 0;  
GO  
RECONFIGURE;  
GO)
  impact 0.5
  tag check_id: 'C-78545r1111121_chk'
  tag severity: 'medium'
  tag gid: 'V-274452'
  tag rid: 'SV-274452r1111123_rule'
  tag stig_id: 'SQLI-22-017100'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-78450r1111122_fix'
  tag 'documentable'
  tag legacy: ['SV-94041', 'V-79335']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
