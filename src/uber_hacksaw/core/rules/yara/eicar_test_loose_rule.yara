rule EICAR_Test_Loose
{
  meta:
    description = "Loose EICAR-like indicator for CI on Windows"
    author = "uber-hacksaw"
    confidence = "low"
  strings:
    $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" nocase
    $b = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" nocase
  condition:
    any of them
}