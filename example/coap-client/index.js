import { CoapClient as coap } from "node-coap-client";
coap.setSecurityParams("localhost", {
	psk: {
		"alice": Buffer.from("9yPztDNbbBkV41JIhL833lfXX+zyBfPaD8VLCK0C88w=", "base64")
	}
});
async function main() {
	try {
		console.log("GET coaps://localhost:5684/hello ...");
		const response = await coap.request("coaps://localhost:5684/hello", "get", undefined);
		const payload = response.payload ? response.payload.toString() : "";
		console.log(`  Response status: ${response.code}`);
		console.log(`  Response payload: ${payload}`);

		console.log("POST coaps://localhost:5684/data " + JSON.stringify({ msg: "Hello I'm Alice" }) + " ...");
		const response2 = await coap.request("coaps://localhost:5684/data", "post", Buffer.from(JSON.stringify({ msg: "Hello I'm Alice" }), "utf-8"));
		const payload2 = response2.payload ? response2.payload.toString() : "";
		console.log(`  Response status: ${response2.code}`);
		console.log(`  Response payload: ${payload2}`);
	} catch (error) {
		console.error("Request failed:", error);
		process.exitCode = 1;
	} finally {
		coap.reset();
	}
}

main();
