for p in policies/*.rego; do
  n=$(basename "$p" .rego); g=${n%%_*}
  c=$(ls policies/tests/ | grep -c "^${g}")
  printf '%-34s %s\n' "$n" "$([ "$c" -gt 0 ] && echo 'has tests' || echo 'NO TESTS')"
done