control 'SV-271362' do
  title 'When invalid inputs are received, the SQL Server must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', 'Review DBMS code (stored procedures, functions, triggers), application code, settings, column and field definitions, and constraints to determine whether the database is protected against invalid input. 

If code exists that allows invalid data to be acted upon or input into the database, this is a finding. 

If column/field definitions are not reflective of the data, this is a finding. 

If columns/fields do not contain constraints and validity checking where required, this is a finding. 

Where a column/field is noted in the system documentation as necessarily free form, even though its name and context suggest that it should be strongly typed and constrained, the absence of these protections is not a finding. 

Where a column/field is clearly identified by name, caption or context as Notes, Comments, Description, Text, etc., the absence of these protections is not a finding.'
  desc 'fix', 'Use parameterized queries, stored procedures, constraints and foreign keys to validate data input. 

Modify SQL Server to properly use the correct column data types as required in the database.'
  impact 0.5
  tag check_id: 'C-75405r1108700_chk'
  tag severity: 'medium'
  tag gid: 'V-271362'
  tag rid: 'SV-271362r1108702_rule'
  tag stig_id: 'SQLI-22-012600'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-75312r1108701_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
