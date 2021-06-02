const async = require('async');
const fs = require('fs');
const gaxios = require('gaxios');
const https = require('https');
const config = require('./config/config');
const errorToPojo = require('./utils/errorToPojo');

const URL = `https://phishstats.info:2096/api/phishing?_where=`;

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
  } catch (err) {
    cb(errorToPojo(err), null);
  }
  Logger.trace({ lookupResults }, 'Lookup results');
  return cb(null, lookupResults);
};

const lookUpEntity = async (entity, done) => {
  let results;
  let res = {};

  const buildEntityQuery = {
    IPv4: (entityValue) =>
      `(ip,like,${entityValue})~or(bgp,like,${entityValue})&_size=20`,
    IPv6: (entityValue) =>
      `(ip,like,${entityValue})~or(bgp,like,${entityValue})&_size=20`,
    domain: (entityValue) =>
      `(host,like,${entityValue})~or(domain,like,${entityValue})&_size=20`,
    SHA256: (entityValue) => `(hash,like,${entityValue})&_size=20`,
    url: (entityValue) => `(url,like,${entityValue})&_size=20`
  };

  try {
    if (buildEntityQuery[entity.type]) {
      results = await gaxios.request({
        url: URL,
        params: {
          querystring: buildEntityQuery[entity.type](entity.value)
        }
      });
    }
  } catch (err) {
    Logger.error(err, 'Error occurred in lookupEntity');
    throw err;
  }

  res.entity = entity;
  res.data = results.data
    ? { summary: [`Phish Results: ${results.data.length}`], details: results.data }
    : null;

  return res;
};

module.exports = {
  doLookup,
  startup
};
