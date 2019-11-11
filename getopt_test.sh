#!/bin/bash

usage(){ 
    echo "Usage: $0 [-iL input_list.txt] [-oL output_list.txt] [-h]" 1>&2;
    echo -e "\n" 1>&2;
    echo -e "-iL, --input-list: input list is a text file that has ASs for each new line in file" 1>&2;
    echo -e "-oL, --output-list: if output list isn't specified then script \n\t will write and replace an output.txt file in current working directory" 1>&2;
    echo -e "-h, --help: help command that shows you how to use the script
    exit 1; 
}

while getopts ":iL:oL:" o; do
    case "${o}" in
        iL)
            iL=${OPTARG}
            if 
            ;;
        oL)
            oL=${OPTARG}
            ;;
        h)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z "${iL}" ] && [ -z "${p}" ]; then
    usage
fi

