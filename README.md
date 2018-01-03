**Just Another Virus Total Submitter**

Simple tool for scan, submit file, hash or directory with files to VirusTotal.<br />
Using public VirusTotal API.<br />
For more details please see https://www.virustotal.com/en/documentation/public-api/ <br />

**Usage:**

If you haven't VirusTotal key, please find 5 min and get your own.
Put it to _config.json_ file.
>```
>   ___       _   _ _____   
>  |_  |     | | | |_   _|  
>    | | __ _| | | | | |___ 
>    | |/ _` | | | | | / __|
>/\__/ / (_| \ \_/ / | \__ \
>\____/ \__,_|\___/  \_/___/
>
>
>Just Another Virus Total Submitter.
>version = 0.1
>
>usage: javts.py [-h] [-get] [-submit] [-hash] [-f] [-d] [-hash_file] [-log]
>                [-v_off]
>
>optional arguments:
>  -h, --help   show this help message and exit
>  -get         Get existing report from Virus Total.
>  -submit      Submit files on Virus Total. Not supported yet.
>  -hash        File hash.
>  -f           File name.
>  -d           Directory with files.
>  -hash_file   File with sha1/sha256/md5 hashes.
>  -log         Store results to log file.
>  -v_off       Turn off verbose mode. Works only if log on.
>
>°º¤ø,¸¸,ø¤º°`°º¤ø,¸,ø¤°º¤ø,¸¸,ø¤º°`°º¤ø,¸
>```

**Examples:**
>```
>  Get report by hash(md5, sha1, sh256): 
>    python3 javts.py -get -hash 3395856ce81f2b7382dee72602f798b642f14140
>  
>  For single file:
>     python3 javts.py -get -f <file name>
>  
>  For folder with files(recursive, subfolder will olso included):
>     python3 javts.py -get -d <folder name, absolute or relative>
>  
>  For file with hashes(could be separated by spaces, new lines or coma):
>    python3 javts.py -get -hash_file <file name>     
>  
>  Store result to log file:
>    python3 javts.py -get -<entity> <value> -log <file name>
>
>  Turn off verbose:
>    -v_off, less info to console, works only with log file on.
>```
