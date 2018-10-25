# Example Files

This directory contains a clear-text RSA private key as an example of converting the PFX file (password: Atredis).

To extract the orion PFX:
```
C:\Temp\> certutil -exportPFX -p Atredis my SolarWinds-Orion orion.pfx
```

To convert the PFX file to PEM:
```$ openssl pkcs12 -in orion.pfx -out orion.pem -nodes -password pass:Atredis```

To decrypt the NCM_GlobalSettings.csv:
```$ ruby ../decrypt-swen-credentials.rb NCM_GlobalSettings.csv```

This produces the decrypted `NCM_GlobalSettings.csv.dec`

