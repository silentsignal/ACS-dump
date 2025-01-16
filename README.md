# Access Client Services Password Dumper

### ACS before CVE-2016-0287

This one works by brute-forcing half of the round 2 key:

```bash
python3 acs_dump_old.py WIN-N6MF export_old.reg
```

### ACS after CVE-2016-0287

This one requires the Build GUID and Product ID from the target machine:

```bash
python3 acs_dump_new.py WIN-46VO ffffffff-ffff-ffff-ffff-ffffffffffff 00431-10000-00000-AA321 export_new.reg
```

