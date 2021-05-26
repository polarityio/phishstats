const async = require('async');
const fs = require('fs');
const gaxios = require('gaxios');
const https = require('https');
const config = require('./config/config');

const BASE_URL = `https://phishstats.info:2096/api/phishing?_where=`;

const _configFieldIsValid = (field) => typeof field === 'string' && field.length > 0;
let Logger;

const startup = (logger) => {
  Logger = logger;

  const {
    request: { ca, cert, key, passphrase, rejectUnauthorized, proxy }
  } = config;

  const httpsAgent = new https.Agent({
    ...(_configFieldIsValid(ca) && { ca: fs.readFileSync(ca) }),
    ...(_configFieldIsValid(cert) && { cert: fs.readFileSync(cert) }),
    ...(_configFieldIsValid(key) && { key: fs.readFileSync(key) }),
    ...(_configFieldIsValid(passphrase) && { passphrase }),
    ...(typeof rejectUnauthorized === 'boolean' && { rejectUnauthorized })
  });

  gaxios.instance.defaults = {
    agent: httpsAgent,
    ...(_configFieldIsValid(proxy) && { proxy: { host: proxy } })
  };
};

const doLookup = async (entities, options, cb) => {
  let lookupResults;

  try {
    lookupResults = await async.parallelLimit(
      entities.map((entity) => async () => {
        const lookupResult = await lookUpEntity(entity);
        return lookupResult;
      }),
      10
    );

    Logger.trace({ IN_LOOK_UP: lookupResults });
  } catch (err) {
    return cb(err, null);
  }

  return cb(null, lookupResults);
};

const lookUpEntity = async (entity, done) => {
  let qualifiedURL;
  let results;

  const buildEntityQuery = {
    IPv4: (entityValue) =>
      BASE_URL + `(ip,like,${entityValue})~or(bgp,like,${entityValue})&_size=20`,
    IPv6: (entityValue) =>
      BASE_URL + `(ip,like,${entityValue})~or(bgp,like,${entityValue})&_size=20`,
    domain: (entityValue) =>
      BASE_URL + `(host,like,${entityValue})~or(domain,like,${entityValue})&_size=20`,
    SHA256: (entityValue) => BASE_URL + `(hash,like,${entityValue})&_size=20`,
    url: (entityValue) => BASE_URL + `(url,like,${entityValue})&_size=20`
  };

  try {
    if (buildEntityQuery[entity.type]) {
      qualifiedURL = buildEntityQuery[entity.type](entity.value);

      results = await gaxios.request({
        url: qualifiedURL
      });
    }
  } catch (err) {
    if (err || results.status !== 200) {
      return err || results;
    }
  }

  Logger.trace({ lookUpResults: results });
  return {
    entity: entity,
    data: { summary: [`Phish Results: ${results.data.length}`], details: results.data }
  };
};

module.exports = {
  doLookup,
  startup
};
