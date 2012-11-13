$computername = 'localhost'
            $memorytype = "Unknown", "Other", "DRAM", "Synchronous DRAM", "Cache DRAM", "EDO", "EDRAM", "VRAM", "SRAM", "RAM", "ROM", "Flash", "EEPROM", "FEPROM", "EPROM", "CDRAM", "3DRAM", "SDRAM", "SGRAM", "RDRAM", "DDR", "DDR-2"
            $formfactor = "Unknown", "Other", "SIP", "DIP", "ZIP", "SOJ", "Proprietary", "SIMM", "DIMM", "TSOP", "PGA", "RIMM", "SODIMM", "SRIMM", "SMD", "SSMP", "QFP", "TQFP", "SOIC", "LCC", "PLCC", "BGA", "FPBGA", "LGA"
            $col1 = @{Name='Size (GB)'; Expression={ $_.Capacity/1GB } }
            $col2 = @{Name='Form Factor'; Expression={$formfactor[$_.FormFactor]} }
            $col3 = @{Name='Memory Type'; Expression={ $memorytype[$_.MemoryType] } }
            $col4 = @{Name='ComputerName'; Expression=[Scriptblock]::Create("'$computername'")}
 
            Get-WmiObject Win32_PhysicalMemory -computername $computername |
 
            Select-Object BankLabel, $col1, $col2, $col3, $col4