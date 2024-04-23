#!/usr/bin/env bash

PROGRESS_FILE="README.md"
NUMBER_OF_CHALLENGES=66

if [ ! -f "$PROGRESS_FILE" ]; then
    echo "[-] Progress file ($PROGRESS_FILE) not found -- aborting !"
fi

latest_challenge_completed=1
declare -a challenges=( $(for i in {1..NUMBER_OF_CHALLENGES}; do echo 0; done) )

# Parse the README content for set checkmark bullet points
while IFS= read -r line; do
    if [[ $line =~ ^-[[:space:]]\[x\][[:space:]](.+)$ ]]; then
        challenge_number=$(echo "${BASH_REMATCH[1]}" | grep -o 'Challenge [[:digit:]]\+' | grep -o '[[:digit:]]\+')
        challenges[challenge_number]=1
        if [[ $challenge_number -gt $latest_challenge_completed ]]; then
            latest_challenge_completed=$challenge_number
        fi
    fi
done < $PROGRESS_FILE

sum=$(IFS=+; echo "$((${challenges[*]}))")
output_string=$(printf "> Progress: %d/%d (%.2f %%) completed (last completed, Challenge %d)\n" "$sum" "$NUMBER_OF_CHALLENGES" "$(bc <<< "scale=2; 100 * $sum / $NUMBER_OF_CHALLENGES")" "$latest_challenge_completed")

echo "$output_string"
sed -i "s|> Progress.*|$output_string|" $PROGRESS_FILE