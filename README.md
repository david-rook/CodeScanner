# CodeScanner
## A proof of concept using ChatGPT to analyse SAST findings and suggest code fixes

⚠️⚠️⚠️ **I used the public ChatGPT API when developing and testing this. Please keep in mind your own security and privacy requirements when using this as code will get sent to ChatGPT if a valid SAST issue is found. Also keep in mind that a valid finding will result in a PR being automatically submitted to a project** ⚠️⚠️⚠️

I put this together to test a theory I had. I wanted to see if we could scan a codebase using a static analysis tool, share the findings and code with the ChatGPT API for analysis and then turn the analysis into suggested code changes. Using the [Bearer SAST](https://github.com/Bearer/bearer) tool and an intentionally [vulnerable application](https://github.com/SasanLabs/VulnerableApp) this was successful. 

To use the script you will need to install Bearer, have an OpenAI API key and a relevant GitHub PAT in config.properties and run this command:

```

codescanner.py --repo-url "github URL to scan"

```

The data flow analysis part of the code is only looking for .java and .js files. The test project only uses those so this would need some modification for other languages that Bearer supports.

Be aware in it's current format it will automatically submit a PR with code changes to the project once a scan has completed. Procede with caution on that part! Also, please don't blindly trust the suggested fix. Review it like you would any other changes.

The images below show Bearer finding a vulnerability in the vulnerable application, we share the finding and code with ChatGPT for true/false positive analysis, as this was a true positive a code fix is applied and an explanation of why it fixes the issue is provided. 

<img width="741" height="145" alt="AISec1" src="https://github.com/user-attachments/assets/2e473d64-e54a-454e-b9f8-75ab21b3c2c2" />
<img width="1566" height="797" alt="AISec2" src="https://github.com/user-attachments/assets/5365586e-7bed-447f-b5f9-fac00422b1b2" />
<img width="1528" height="567" alt="AISec3" src="https://github.com/user-attachments/assets/d31af47b-9490-4dbd-9af6-46a11296d231" />
<img width="1532" height="273" alt="AISec4" src="https://github.com/user-attachments/assets/017bcb6b-2537-4c77-9ab4-c5c5f963cddc" />
