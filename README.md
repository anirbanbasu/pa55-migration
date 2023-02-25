![CodeQL](https://github.com/anirbanbasu/pa55-migration/actions/workflows/codeql.yml/badge.svg?branch=master&event=push)

# Command line migration tool for PA55NYAPS

## Summary
This command line migration tool for PA55NYAPS ([GitHub](https://github.com/pa55/pa55nyaps/)) generates the password for each PA55NYAPS password database entry and exports the generated password along with relevant information as JSON or CSV in order to import into any other password manager. When exported as JSON, for PA55NYAPS, the file contains the entire password database including the settings for each password database entry along with the corresponding generated password. If the exported file is CSV, information about character classes are dropped.

## How to use

You can build the executable JAR from the source code. Or, you can download the executable JAR from an appropriate release and run the JAR as instructed below.

### Build
This project uses Apache Maven. Ensure that your operating environment contains Maven (>=3.9) and Java SDK (e.g., OpenJDK >=19.0.2). In order to compile and package the tool as an executable JAR, execute `mvn clean compile assembly:single`. The output of the build, if successful, will contain a line akin to `[INFO] Building jar: <current-directory>/target/tools-0.0.1-SNAPSHOT-jar-with-dependencies.jar`.

Note that the project can also be built using Gradle but it is experimental as of now.

### Generate Software Bill of Materials (SBOM)
Software Bill of Materials (SBOM) for the project can be generated in both CycloneDX ([GitHub](https://github.com/CycloneDX/cyclonedx-maven-plugin)) and SPDX ([GitHub](https://github.com/spdx/spdx-maven-plugin)) formats by executing `mvn cyclonedx:makeAggregateBom` and `mvn spdx:createSPDX` respectively. In case of CycloneDX, the output will be in both JSON and XML formats while it will be only JSON for SPDX. The locations of the SBOM files will be printed during the SBOM generation processes.

### Run
The JAR file generated in the build step can be executed, in the same directory as the project, as `java -jar target/tools-<version>-jar-with-dependencies.jar -h`. (Check the releases or the output of the build to pick an appropriate value for the `<version>`.) The `-h` option prints the usage information as follows, which is rather self-explanatory.

```
usage: tools.migration.PasswordDatabaseExporter [-c] [-g] [-h] -i <input
       file> -o <output file>
 -c,--csv                    Output a CSV line for each database entry
                             instead of JSON.
 -g,--generate               Generate passwords for each database entry.
 -h,--help                   Print this help message.
 -i,--input <input file>     Input PA55 NYAPS encrypted password database
                             file path.
 -o,--output <output file>   Output PA55 NYAPS plaintext password database
                             file path. Output file will contain generated
                             passwords if -g is specified.
```

Thus, a CSV file may be exported with the generated passwords by executing `java -jar target/tools-0.0.1-SNAPSHOT-jar-with-dependencies.jar -cg -i <input-PA55NYAPS-file-path> -o <output-CSV-file-path>`. The migration tool will ask the user to type in the file decryption password in order to decrypt the PA55NYAPS password database file. It will also ask for the master secret when the `-g` option is specified.

**WARNING:** If the exported file is created using the `-g` option then the file will contain _passwords in plaintext_.
