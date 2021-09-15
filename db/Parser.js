exports.getCredentials = (body) => {
	const output = {};
	output.login = body.login;
	output.pass = body.pass;
	return output;
}