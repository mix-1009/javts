#Just Another Virus Total Submitter

Simple tool for scan, submit file, hash or directory with files to VirusTotal.
Using publiv VirusTotal API.
For more details please see https://www.virustotal.com/en/documentation/public-api/

#Usage

If you haven't VirusTotal key, please find 5 min and get your own.
Put it to config.json file.

   ___       _   _ _____   
  |_  |     | | | |_   _|  
    | | __ _| | | | | |___ 
    | |/ _` | | | | | / __|
/\__/ / (_| \ \_/ / | \__ \
\____/ \__,_|\___/  \_/___/

Just Another Virus Total Submitter.
version = 0.1

usage: javts.py [-h] [-get] [-submit] [-hash] [-f] [-d]

optional arguments:
  -h, --help  show this help message and exit
  -get        Get existing report from Virus Total.
  -submit     Submit files on Virus Total. Not supported yet.
  -hash       File hash.
  -f          File name.
  -d          Directory with files.


°º¤ø,¸¸,ø¤º°`°º¤ø,¸,ø¤°º¤ø,¸¸,ø¤º°`°º¤ø,¸

Examples:
  Get report by hash(md5, sha1, sh256): 
    python3 javts.py -get -hash 3395856ce81f2b7382dee72602f798b642f14140
  
  For single file:
     python3 javts.py -get -f <file name>
  
  For folder with files(recursive, subfolder will olso included):
     python3 javts.py -get -d <folder name, absolute or relative>
     
     
