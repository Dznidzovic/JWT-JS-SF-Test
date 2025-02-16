//import forge from "https://cdnjs.cloudflare.com/ajax/libs/forge/0.10.0/forge.min.js";

// Encodes a string to Base64 URL-safe format
export function base64UrlEncode(str) {
    return btoa(str) // Ensures Unicode support
        .replace(/\+/g, "-")  // Replace '+' with '-'
        .replace(/\//g, "_")  // Replace '/' with '_'
        .replace(/=+$/, "");  // Remove '=' padding
}

// Generates a JWT token for Salesforce authentication
export function generateJWT(
    algorithm = 'RS256',
    type = 'JWT',
    issuer,
    audience,
    subscriber,
    expiration = Math.floor(Date.now() / 1000) + 300,
    privateKey
) {
    try {
        if (!issuer || !audience || !subscriber || !privateKey) {
            throw new Error("Missing required parameters for JWT generation.");
        }

        // Construct JWT header
        const header = {
            alg: algorithm,
            typ: type
        };

        // Construct JWT payload
        const payload = {
            iss: issuer,
            aud: audience,
            sub: subscriber,
            exp: expiration // Expiration timestamp in seconds
        };

        // Encode header and payload using Base64 URL-safe encoding
        const encodedHeader = base64UrlEncode(JSON.stringify(header));
        const encodedPayload = base64UrlEncode(JSON.stringify(payload));

        // Load private key from PEM format
        const forgedPrivateKey = forge.pki.privateKeyFromPem(privateKey);

        // Create the message to sign (header + payload)
        const message = `${encodedHeader}.${encodedPayload}`;

        // Create a SHA-256 hash of the message
        const md = forge.md.sha256.create();
        md.update(message, "utf8");

        // Sign the hash using the RSA private key and encode it in Base64URL format
        const signature = forge.util.encode64(forgedPrivateKey.sign(md))
            .replace(/\+/g, "-") 
            .replace(/\//g, "_") 
            .replace(/=+$/, ""); 

        // Construct the final JWT
        const jwt = `${encodedHeader}.${encodedPayload}.${signature}`;
        console.log("Generated JWT:", jwt);

        return jwt;
    } catch (error) {
        console.error("JWT Generation Error:", error);
        return null;
    }
}

/**
 * Exchanges a JWT for an OAuth access token in Salesforce
 * @param {string} jwt - The generated JWT
 * @param {string} [proxyURL=""] - Optional proxy URL
 * @returns {Promise<string>} - OAuth access token
 */
export async function getAccessTokenWithJWT(jwt, proxyURL = "") {
    try {
        if (!jwt) {
            throw new Error("JWT is required to obtain an access token.");
        }

        const salesforceTokenURL = "https://login.salesforce.com/services/oauth2/token";

        const fullURL = proxyURL + encodeURIComponent(salesforceTokenURL);

        const tokenResponse = await fetch(fullURL, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jwt })
        });

        const tokenData = await tokenResponse.json();

        if (!tokenResponse.ok) {
            throw new Error(`Token Error: ${tokenData.error_description}`);
        }

        console.log("Access Token:", tokenData.access_token);
        return tokenData.access_token;
    } catch (error) {
        console.error("Error obtaining access token:", error);
        return null;
    }
}