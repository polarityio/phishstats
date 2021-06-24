const async = require('async');
const fs = require('fs');
const gaxios = require('gaxios');
const https = require('https');
const config = require('./config/config');
const errorToPojo = require('./utils/errorToPojo');

const URL = `https://phishstats.info:2096/api/phishing?`;
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
        const lookupResult = await lookUpEntity(entity, options);
        return lookupResult;
      }),
      10
    );
  } catch (err) {
    let detailMsg = 'There was an unexpected error';

    if (err.response) {
      detailsMsg = `Received unexpected HTTP status ${err.response.status}`;
    } else if (err.request) {
      detailsMsg = `There was an HTTP err`;
    } else {
      detailMsg = err.message;
    }
    return cb(errorToPojo(detailMsg, err));
  }

  Logger.trace({ lookupResults }, 'Lookup results');
  return cb(null, lookupResults);
};

const lookUpEntity = async (entity, options) => {
  let results;

  const buildEntityQuery = {
    IPv4: (entityValue) =>
      `_where=(ip,eq,${entityValue})~or(bgp,eq,${entityValue})&_size=10`,
    IPv6: (entityValue) =>
      `_where=(ip,eq,${entityValue})~or(bgp,eq,${entityValue})&_size=10`,
    domain: (entityValue) =>
      `_where=(host,eq,${entityValue})~or(domain,eq,${entityValue})&_size=10`,
    hash: (entityValue) => `_where=(hash,eq,${entityValue})&_size=10`
  };

  if (buildEntityQuery[entity.type]) {
    results = await gaxios.request({
      url: URL + buildEntityQuery[entity.type](entity.value),
      params: {
        querystring: {
          type: entity.type,
          value: entity.value
        }
      }
    });

    return (lookupResult = {
      entity,
      data:
        Array.isArray(results.data) && results.data.length > 0
          ? { summary: getSummary(results.data), details: results.data }
          : null
    });
  }
};

const getSummary = (data) => {
  let tags = [];
  const totalResults = data.length;
  tags.push(`Results: ${totalResults}`);
  return tags;
};

module.exports = {
  doLookup,
  startup
};

