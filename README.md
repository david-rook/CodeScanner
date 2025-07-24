# CodeScanner
## A proof of concept using AI to analyse SAST findings and suggest code fixes

⚠️⚠️⚠️ **I used the public ChatGPT and Claude API's when developing and testing this. Please keep in mind your own security and privacy requirements when using this as code will get sent to ChatGPT and Claude if a valid SAST issue is found. Also keep in mind that a valid finding will result in a PR being automatically submitted to a project** ⚠️⚠️⚠️

I put this together to test a theory I had. I wanted to see if we could scan a codebase using a static analysis tool, share the findings and code with the ChatGPT and Claude for analysis and then turn the analysis into suggested code changes. Using the [Bearer SAST](https://github.com/Bearer/bearer) tool and and a few intentionally vulnerable applications this has been proved to be a potential use for AI in security reviews. 

To use the script you will need to install Bearer, have an OpenAI API or Claude API key and a relevant GitHub PAT in config.properties or claudepconfig.properties and run this command:

```

codescanner.py --repo-url "github URL to scan" or codescanner_claude.py --repo-url "github URL to scan"

```

I've used [tree-sitter](https://tree-sitter.github.io/tree-sitter/) to generate the AST's for the code base. You will need to install this and the relevant languages (currently the scanner supports the same languages as the free Bearer scanner) to run the scanners which in turn run the AST generator.  

Be aware in it's current format it will automatically submit a PR with code changes to the project once a scan has completed. Procede with caution on that part! Also, please don't blindly trust the suggested fix. Review it like you would any other changes.

The images below show Bearer finding a vulnerability in the vulnerable application, we share the finding and code with ChatGPT and Claude for true/false positive analysis, as this was a true positive a code fix is applied and an explanation of why it fixes the issue is provided. 

<img width="741" height="145" alt="AISec1" src="https://github.com/user-attachments/assets/2e473d64-e54a-454e-b9f8-75ab21b3c2c2" />
<img width="1566" height="797" alt="AISec2" src="https://github.com/user-attachments/assets/5365586e-7bed-447f-b5f9-fac00422b1b2" />
<img width="1528" height="567" alt="AISec3" src="https://github.com/user-attachments/assets/d31af47b-9490-4dbd-9af6-46a11296d231" />
<img width="1532" height="273" alt="AISec4" src="https://github.com/user-attachments/assets/017bcb6b-2537-4c77-9ab4-c5c5f963cddc" />
