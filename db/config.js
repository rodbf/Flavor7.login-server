const login = require('./login');

const config = {
	development: {
		database: {
			connectionLimit: 10,
			host: login.dev.host,
			database: login.dev.database,
			user: login.dev.user,
			password: login.dev.password
		}
	}
}

module.exports = config;