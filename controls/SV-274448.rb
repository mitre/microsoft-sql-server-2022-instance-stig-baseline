control 'SV-274448' do
  title 'The SQL Server Service Broker endpoint must use AES encryption.'
  desc 'Information can be unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring that data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

SQL Server Service Broker endpoints support different encryption algorithms, including no-encryption. Using a weak encryption algorithm or plaintext in communication protocols can lead to data loss, data manipulation, and/or connection hijacking.'
  desc 'check', 'If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, and the requirement is documented and authorized, this is not a finding.

If SQL Service Broker is in use, run the following to check for encrypted transmissions:  

SELECT name, type_desc, encryption_algorithm_desc
FROM sys.service_broker_endpoints
WHERE encryption_algorithm != 2

If any records are returned, this is a finding.'
  desc 'fix', 'Run the following to enable encryption on the Service Broker endpoint:

ALTER ENDPOINT <EndpointName>
FOR SERVICE_BROKER
(ENCRYPTION = REQUIRED ALGORITHM AES)'
  impact 0.5
  tag check_id: 'C-78541r1111110_chk'
  tag severity: 'medium'
  tag gid: 'V-274448'
  tag rid: 'SV-274448r1111112_rule'
  tag stig_id: 'SQLI-22-016600'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-78446r1111111_fix'
  tag 'documentable'
  tag legacy: ['SV-94031', 'V-79325']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
