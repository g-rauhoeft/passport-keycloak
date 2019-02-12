var OAuth2Strategy = require('passport-oauth2')
  , util = require('util');

function Strategy(options, verify) {
  options = options || {};
  options.realm = options.realm || 'master';
  options.authorizationURL = options.authorizationURL || `auth/realms/${options.realm}/protocol/openid-connect/auth`;
  options.tokenURL = options.tokenURL || `auth/realms/${options.realm}/protocol/openid-connect/auth`;
  options.clientID = options.clientID || 'account';
  options.scopeSeparator = options.scopeSeparator || ',';
  options.customHeaders = options.customHeaders || {};

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-keycloak';
  }

  OAuth2Strategy.call(this, options, verify);
  this.name = 'keycloak';
  this._userProfileURL = options.userProfileURL || `auth/realms/${options.realm}/protocol/openid-connect/userinfo`;
  this._oauth2.useAuthorizationHeaderforGET(true);
}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, _) {
    var profile;
    if (err) {
      return done(err);
    }
    
    try {
      profile = JSON.parse(body);
    } catch (e) {
      return done(e);
    }
    
    profile.provider  = 'keycloak';

    done(null, profile);
  });
}

module.exports = Strategy;