# SSTIC2019
SSTIC2019 Challenge - All steps solutions

Challenge description: https://www.sstic.org/2019/challenge/
Challenge file: http://static.sstic.org/challenge2019/challenge_SSTIC_2019-virtual_phone.tar.gz

All scripts work using Python3

## Step1
  - breakingRSA-Final.ipynb: Jupyter Notebook containing an implemented algorithm to break the RSA key using a Single Power Analysis
 
## Step2
  - get_safe1_key_final.py: python script containing the implementation of schematics.png, and the bruteforce code

## Step3
  - 01_dwarf_exp_disassembler_3.py: this is a disassembler for disassembling the dwarf code of the Step3
  - 02_dwarf_emulator_pythonImpl_v2.py: emulator for the dwarf code
  - 03_pythonImplemOptimized_final.py: optimized python implementation of the dwarf code, and reverse algorithm to find the Step3 correct input
  
  Note that only a subset of dwarf specification instructions is implemented (only those relevant to the challenge)

## Step4
Input files for the Step4 challenge
  - flash.bin: binary containing Step4 trusted firmware and EL3 files (ciphered files bl2, bl31, bl32 + filesystem)
  - sstic.ko: sstic kernel driver used by the Step4
  - decrypted_file: entry point of Step4

Scripts:
  - SM4.py: implementation of custom SM4 algorithm used by the Step4. Python module used by some of the following scripts
  - 00_file_extraction_script.py: this script enable to extract and decipher bl2.bin, bl31.bin, bl32.bin files, from flash.bin file
  - 01_write_payload_to_binary_file.py: in this Step4, there are 0x101010 bytes deciphered using custom SM4 algorithm. These bytes have been copied in this script, in order to put them into a binary file (still encrypted)
  - 02_decipher_payload.py: script to decipher ciphered_payload.bin into decrypted_payload.bin
  - 03_reverse_final_function.py: script containing the reverse of the VM of the Step4, keeping function address names and smc LSB naming. This script also contains some pseudo-code written for each VM opcode, in order to enable the final reverse
  - 04_reversing_bis.py: script containing reworked pseudo-code extracted from the previous script, with custom notes to watch the evolution of the VM registers
  - 05_solution_cracking.py: script containing the reversed pseudo-code to find the Step4 correct input
