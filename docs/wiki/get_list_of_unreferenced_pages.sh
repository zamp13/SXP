#!/bin/sh
#
# this script prints the list of pages that aren't pointed to

# get list of existing pages
ls --color=none *.md > /tmp/sxp_ls

# get list of pages referenced
cat * | grep "(\/SXP\/wiki\/" | sed "s/^.*(\/SXP\/wiki\///g" | sed "s/ \"wikilink\".*$//g" | sed "s/$/.md/g" > /tmp/sxp_grep_links

# compare: step 1
rm -f /tmp/sxp_ls2
for i in $(cat /tmp/sxp_ls)
do
  # head -1 is here to keep only one occurrence
  grep "^${i}" /tmp/sxp_grep_links | head -1 >> /tmp/sxp_ls2
done

# compare: step 2
diff /tmp/sxp_ls /tmp/sxp_ls2

# remove tmp files
#rm /tmp/sxp_grep_links /tmp/sxp_ls /tmp/sxp_ls2

