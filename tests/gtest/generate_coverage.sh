#!/bin/bash

lcov --rc branch_coverage=1 --capture --directory /home/frr/frr/zebra/ \
                            --include '/home/frr/frr/zebra/*' \
                            --include '/home/frr/frr/lib/*' \
                            --output-file coverage.info \
                            --ignore-errors mismatch,inconsistent,corrupt
                            

#if [ -f .lcovrc ]; then
#    while IFS= read -r line; do
#        if [[ $line == lcov_filter=* ]]; then
#            filter=${line#lcov_filter=}
#            echo $filter
#            lcov --remove coverage.info "$filter" --output-file coverage.info
#            echo "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"
#        elif [[ $line == lcov_filter_function=* ]]; then
#            func=${line#lcov_filter_function=}
#            echo $func
#            lcov --remove  coverage.info "*$func*" --output-file coverage.info
#            echo "ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"
#        fi
#    done < .lcovrc
#fi

# 读取排除函数的正则表达式文件
regex_file="exclude_functions.txt"

# 检查文件是否存在
if [ ! -f "$regex_file" ]; then
    echo "Error: $regex_file does not exist."
    exit 1
fi

# 初始化一个空数组来保存所有的 --erase-functions 参数
declare -a erase_functions=()

# 读取文件的每一行，并为每一行添加 --erase-functions 参数后添加到 erase_functions 数组中
while IFS= read -r line || [[ -n $line ]]; do
    # 直接将每行作为参数添加到 erase_functions 数组中
    erase_functions+=("--erase-functions" "$line")
done < "$regex_file"

genhtml coverage.info --rc branch_coverage=1 --output-directory coverage/html --title "zebra coverage" --show-details --legend --ignore-errors mismatch,inconsistent,corrupt \
    "${erase_functions[@]}"
echo "Coverage report generated in coverage/html/index.html"