# Version 4.0.0 - yyyy-mm-dd

- Changed the decoded value of TXT records to an array of Buffers. This is to accomodate DNS-SD records which rely on the individual strings record being separated.
- Renamed the `flag_trunc` and `flag_auth` to `flag_tc` and `flag_aa` to match the names of these in the dns standards.
