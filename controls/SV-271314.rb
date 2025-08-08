control 'SV-271314' do
  title 'SQL Server must use NIST FIPS 140-2 or 140-3 validated cryptographic operations for encryption, hashing, and signing.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of using encryption and digital signatures to protect data. Weak algorithms can be easily broken, and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to, and modify data stored in, the database as well as the administration settings of SQL Server. 
 
Applications, including DBMSs, using cryptography are required to use approved NIST FIPS 140-2 or 140-3 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.  
 
NSA Type- (where =1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The standard for validating cryptographic modules will transition to the NIST FIPS 140-3 publication.

FIPS 140-2 modules can remain active for up to five years after validation or until September 21, 2026, when the FIPS 140-2 validations will be moved to the historical list. Even on the historical list, CMVP supports the purchase and use of these modules for existing systems. While Federal Agencies decide when they move to FIPS 140-3 only modules, purchasers are reminded that for several years there may be a limited selection of FIPS 140-3 modules from which to choose. CMVP recommends purchasers consider all modules that appear on the Validated Modules Search Page:
https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules

More information on the FIPS 140-3 transition can be found here: 
https://csrc.nist.gov/Projects/fips-140-3-transition-effort/.

'
  desc 'check', 'Verify that Windows is configured to require the use of FIPS compliant algorithms. 
 
1. Click "Start".
2. Type "Local Security Policy".
3. Press "Enter".
4. Expand "Local Policies".
5. Select "Security Options".
6. Review the Security Setting for "System Cryptography:  Use FIPS compliant algorithms for encryption, hashing, and signing". 
 
If the Security Setting for this option is "Disabled", this is a finding.

Alternatively, run the following code in PowerShell:

Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy | Select Enabled

If the returned value is "0", this is a finding.'
  desc 'fix', 'Configure Windows to require the use of FIPS compliant algorithms for the unclassified information that requires it. 
 
1. Click "Start".
2. Type "Local Security Policy".
3. Press "Enter". 
4. Expand "Local Policies". 
5. Select "Security Options".
6. Locate "System Cryptography:  Use FIPS compliant algorithms for encryption, hashing, and signing". 
7. Change the Setting option to "Enabled". 
8. Restart Windows.'
  impact 0.7
  tag check_id: 'C-75357r1109018_chk'
  tag severity: 'high'
  tag gid: 'V-271314'
  tag rid: 'SV-271314r1109121_rule'
  tag stig_id: 'SQLI-22-008700'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-75264r1109019_fix'
  tag satisfies: ['SRG-APP-000179-DB-000114', 'SRG-APP-000176-DB-000068', 'SRG-APP-000224-DB-000384', 'SRG-APP-000514-DB-000381', 'SRG-APP-000514-DB-000382', 'SRG-APP-000514-DB-000383']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-000186', 'CCI-001188', 'CCI-002450']
  tag nist: ['IA-7', 'IA-5 (2) (a) (1)', 'SC-23 (3)', 'SC-13 b']
end
