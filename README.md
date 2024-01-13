# Proteus

Proteus is a mock API server. I built this tool to cover these 2 use cases:
1. to unblock the development of the client side applications, when the backend / third-party API is not ready / available yet
2. to test that webhooks are sent correctly by letting Proteus receive them

Before Proteus, I had to:
- either mock the API responses manually via the JSON files
- use Wiremock and write some code to make it work.

Both of these approaches are not ideal, as JSON files are not flexible enough and Wiremock approach is time-consuming. 
The idea behind Proteus is to simplify this and cover the most common use cases.

The name Proteus comes from the Greek mythology. Proteus is a god of rivers and oceans, who can change his shape. 
The ability to change the shape resonates with the idea of this tool.

Please note that the tool is still in the early development stage, so the API might change in the future.
There still might be some bugs, so please, feel free to report them.

[//]: # (TODO: Add description)