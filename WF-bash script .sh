#!/bin/bash

# Project Windows Forensics

#Installing Figlet (Not mentioned in the script. Only for decorative usage)
if [ -d /usr/share/figlet ]
then
	echo -e "\033[0;32mFiglet is already installed \033[0m"
else
	echo -e "\033[0;31m[!] Figlet could not be found. Installing now. \033[0m"
	sudo apt-get install figlet 1>/dev/null
fi

#Installing Volatility
# Check if Volatility exists
if [ -x "$(command -v volatility)" ]; then
  echo -e "\033[0;32mVolatility is already installed \033[0m"
else
  echo -e "\033[0;31m[!] Volatility could not be found. Installing now. \033[0m"

  # Installing Volatility
  echo -e "\033[0;31mInstalling Volatility...\033[0m"
  sudo apt-get update 1>/dev/null
  sudo apt-get install -y volatility 1>/dev/null

  # Verify installation
  if [ -x "$(command -v volatility)" ]; then
    echo -e "\033[0;31mVolatility has been installed successfully.\033[0m"
  else
    echo -e "\033[0;31m[!] Failed to install Volatility.\033[0m"
  fi
fi

# Installing foremost
# Check if foremost exists
if [ -x "$(command -v foremost)" ]; then
  echo -e "\033[0;32mforemost is already installed \033[0m"
else
  echo -e "\033[0;31m[!] foremost could not be found. Installing now. \033[0m"

  # Installing foremost
  echo -e "\033[0;31mInstalling foremost...\033[0m"
  sudo apt-get update 1>/dev/null
  sudo apt-get install -y foremost 1>/dev/null

  # Verify installation
  if [ -x "$(command -v foremost)" ]; then
    echo -e "\033[0;31mforemost has been installed successfully.\033[0m"
  else
    echo -e "\033[0;31m[!] Failed to install foremost.\033[0m"
  fi
fi

# 1. Automate HDDm the given, binary image for ending files and executable code
# 1.1 Verify user is root
if [ "$(whoami)" != "root" ]
then
	echo -e "\033[0;31 [x]:: You are not root. Please exit. \033[0m"
	exit
fi

# 1.2 Allow the user to specify the filename; check if the file exists 

	echo -e "\033[0;32m Please enter a Memory or a HDD filename: \033[0m"
	read filename

if [ -e "$filename" ];
	then
		echo -e "\033[0;32m [✔]File $filename exists!\033[0m"
	else
		#no' 31= red output
		echo -e "\033[0;31m The file does not exist.\033[0m"
fi	

# Specify whether the file entered is a memory or image file in order to apply appropriate.
read -p "Please enter a memory file or an image file: " FILE

read -p "Select M for a memory file or I for an image file: " SEL

#(1) Extracting from the given, binary image for enbedded files and executable code.

function BNWLK ()
{
	echo -e "\033[0;32m[*]:: Extracting binwalk data ...\033[0m"
	echo -e "\033[0;32m[*]:: Please be patient ...\033[0m"
	binwalk $FILE > file_binwalk 2>/dev/null
	echo -e "\033[0;32m[✔]:: Extracted. \033[0m"
	echo "==============================================================================================" | lolcat
}

#(2)Scans the disk image and extracts useful information without parsing the file system or file system structures.

function BULK ()
{
	echo -e "\033[0;32m [*]:: Extracting bulk_extractor data ...\033[0m"
	echo -e "\033[0;32m[*]:: Please be patient ...\033[0m"
	bulk_extractor $FILE -o file_bulk 1>/dev/null
	echo -e "\033[0;32m [✔]:: Extracted. \033[0m"
	echo "==============================================================================================" | lolcat
}

#(3) Extracting lost files based on their headers, footers and internal data structures.

function FOREM ()
{
	echo -e "\033[0;32m[*]:: Extracting foremost data ...\033[0m"
	echo -e "\033[0;32m[*]:: Please be patient ...\033[0m"
	foremost $FILE -t all -o file_forem 1>/dev/null
	echo -e "\033[0;32m[✔]:: Extracted. \033[0m"
	echo "==============================================================================================" | lolcat
}

#(4) Extracting strings from your mem file.

function STR ()
{
	echo -e "\033[0;32m[*]:: Extracting strings data ...\033[0m"
	echo -e "\033[0;32m[*]:: Please be patient ...\033[0m"
	strings $FILE > file_strings 1>/dev/null
	echo -e "\033[0;32m[✔]:: Extracted. \033[0m"
	echo "==============================================================================================" | lolcat
}

#(5) Extracting RAM information.

function VOL ()
{
	echo -e "\033[0;32m[✔]:: Extracting imageinfo ... \033[0m" 1>/dev/null
	./vol -f $FILE imageinfo > file_profile 2>/dev/null
	FILE_PROFILE=$(cat file_profile | grep -i suggested | awk '{print $4}' | awk -F ',' '{print $1}')
	VOLDATA="pslist pstree userassist sockets"
	
	for i in $VOLDATA
	do
		echo -e "\033[0;32m[✔]:: Extracting $i data ...\033[0m"
		./vol -f $FILE --profile=$FILE_PROFILE $i > $i.txt 2>/dev/null
	done
		echo "==============================================================================================" | lolcat
}

# Collecting data from the extracted files.

function LOG ()
{
	LOGDATA='txt exe gif wav dll pcap'
	
	for i in $LOGDATA
	do
		echo -e "\033[0;32m[✔]:: Extracting $i files. \033[0m"
		find . -type f -name "*.$i" | awk -F '/' '{print $NF}' 1>/dev/null
		echo -e "\033[0;32m[✔]:: Calculated $i extracting files. \033[0m"
		find . -type f -name "*.$i" | awk -F '/' '{print $NF}' | wc -l 1>/dev/null
	done
} > yourmem_log


# Running the function according to the type file.

case $SEL in

M)
	figlet "$MEM This is a memory file." | lolcat
	echo 
	echo "==============================================================================================" | lolcat
# Execute the functions
	BULK
	BNWLK
	FOREM
	STR
	VOL
	sleep 0.2
;;
I)
	figlet "[✔]:: Confirm $MEM image file" | lolcat
	
	echo "==============================================================================================" lolcat
# Execute the functions
	BULK
	BNWLK
	FOREM
	STR
	VOL
	sleep 0.2
;;
esac

# [✔] Sucsess [✔]

echo "==============================================================================================" | lolcat

figlet -f mono9 "Extracting data file" | lolcat

# Execute function LOG
LOG

echo "==============================================================================================" | lolcat
echo -e "\033[0;33mYour log data has been saved to 'file' log :) \033[0m"

#apt install cbonsai 1>/dev/null
#cbonsai -lp
