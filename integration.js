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
    // baseUrl: BASE_URL,
    agent: httpsAgent,
    ...(_configFieldIsValid(proxy) && { proxy: { host: proxy } })
  };
};

const lookUpEntity = async (entity, done) => {
  let qualifiedURL;
  let results;

  const buildEnitityQuery = {
    isIP: (entity) => BASE_URL + `(ip,like,${entity.value})~or(bgp,like,${entity.value})`,
    isDomain: (entity) =>
      BASE_URL + `(host,like,${entity.value})~or(domain,like,${entity.value})`,
    isSHA256: (entity) => BASE_URL + `(hash,like,${entity.value})`,
    isURL: (entity) => BASE_URL + `(url,like,${entity.value})`
  };

  for (const entityType of Object.keys(entity)) {
    try {
      if (buildEnitityQuery[entityType] && entity[entityType]) {
        qualifiedURL = buildEnitityQuery[entityType](entity);

        results = await gaxios.request({
          url: qualifiedURL
        });
      }
    } catch (err) {
      if (err || results.status !== 200) {
        done(err || results);
      }
    }
  }
  done(null, {
    entity: entity,
    data: {
      summary: [entity.value],
      details: results.data
    }
  });
  Logger.trace({ lookUpResults: results });
};

const doLookup = async (entities, options, cb) => {
  let lookupResults = [];

  for (const entity of entities) {
    try {
      await lookUpEntity(entity, (err, result) => {
        if (!err) {
          lookupResults.push(result);
        }
      });
    } catch (err) {
      return cb(err, null);
    }
  }
  cb(null, lookupResults);
};

module.exports = {
  doLookup,
  startup
};
