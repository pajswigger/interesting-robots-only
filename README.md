# Interesting Robots Only

This Burp extension reports a scan issue when robots.txt is identified with interesting content. For this to be useful
you need to disable the built in "Robots.txt file" check.

The logic used by the script is:

 * Blank lines, comments and User-Agent lines are not interesting.
 * Allow or Disallow / is not interesting.
 * Anything else is intersting.