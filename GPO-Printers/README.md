# GPO printer mappings from a CSV

`Update-GPOPrinterMappings.ps1` updates the Group Policy Preferences shared printers in a GPO,
including the group Item Level Targeting, from a CSV. It looks up the group SIDs for you, so you
only need to put group names in the CSV.

## How it works

GPP printers live in one XML file in SYSVOL:

```
\\<domain>\SYSVOL\<domain>\Policies\{GPO-GUID}\User\Preferences\Printers\Printers.xml
```

The script reads that file to CSV, or writes a new one from a CSV. After writing it bumps the GPO
version number (in AD and GPT.INI) so clients see the change. Everything is done against the PDC.

## Typical run for a print server move

1. Copy the live GPO in GPMC and link the copy to a test OU. Do all this against the copy first.
2. Export what is there now:
   ```powershell
   .\Update-GPOPrinterMappings.ps1 -Mode Export -GpoName 'Printers - TEST' -CsvPath .\printers.csv
   ```
   Or, if the new server already has all its queues shared, build the CSV from that instead:
   ```powershell
   .\Update-GPOPrinterMappings.ps1 -Mode Template -PrintServer NEWPRINT01 -OldPrintServer OLDPRINT01 -GroupNameFormat 'PRN-{0}' -CsvPath .\printers.csv
   ```
3. Open the CSV in Excel. Change the server in `Path`, fix up `Groups`, add the new printers,
   and put the old path in `OldPath` if you want the old connection removed.
4. Dry run. This checks every group exists in AD and every share exists on the print server,
   and saves the XML it would write to your temp folder. Nothing is changed.
   ```powershell
   .\Update-GPOPrinterMappings.ps1 -Mode Import -GpoName 'Printers - TEST' -CsvPath .\printers.csv -WhatIf
   ```
5. Run it for real (same command without `-WhatIf`). It backs up the GPO to `.\GPOBackups` first.
6. Open the GPO in GPMC and check a few items and their targeting. Log on as a test user and run
   `gpupdate /force`, then `gpresult /h report.html`.

## CSV columns

| Column   | What goes in it |
|----------|-----------------|
| Name     | Name shown in GPMC. Blank = share name |
| Path     | `\\server\share` of the printer |
| Action   | `U` Update (default), `C` Create, `R` Replace, `D` Delete |
| Default  | `1` to make it the default printer, else `0` |
| Groups   | `Group` or `DOMAIN\Group`. More than one? Separate with `;` and they are OR'd |
| OldPath  | Optional old `\\server\share`. Adds a Delete item for it, with no targeting |
| Location | Optional |
| Comment  | Optional |

See `printers-example.csv`.

## Things to know

- The CSV is the whole list. Any printer in the GPO that is not in the CSV is removed on import.
  Export first so you don't lose anything.
- Only shared printers with group targeting are handled. Other targeting (OU, computer name,
  IP range, etc) is flagged on export and is not carried over.
- Needs GPMC / RSAT on the machine you run it from, and rights to edit the GPO.
  The AD PowerShell module is not needed.
- If it goes wrong, restore from the backup with `Restore-GPO -BackupId <id> -Path .\GPOBackups`,
  or in GPMC under Group Policy Objects > Manage Backups.
