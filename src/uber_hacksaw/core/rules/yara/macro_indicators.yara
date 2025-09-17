rule Macro_Indicators
{
  meta:
    description = "Detects macro indicators in documents"
    author = "uber-hacksaw"
    severity = "high"
    confidence = "medium"
  strings:
    $vba = "VBA" nocase
    $macro = "Macro" nocase
    $auto_open = "Auto_Open" nocase
    $auto_close = "Auto_Close" nocase
  condition:
    2 of them
}