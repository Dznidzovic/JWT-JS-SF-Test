Examples of direct browser Javascript calls to Salesforce Rest APIs using OAuth 2.0 flows.
All of these methods require manually storing certain credentials and utilizing free proxy servers for token generation which are not secure.

This is a workaround for scenarios where backend is not available and you are strictly running a frontend application and for whatever reason you want to connect to Salesforce Rest APIs without even utilizing a proxy server which could be easily set up with Nodejs and Heroku.

Each Branch Name represents an OAuth 2.0 flow used for auth.
