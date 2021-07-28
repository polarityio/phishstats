const async = require('async');
const fs = require('fs');
const gaxios = require('gaxios');
const https = require('https');
const config = require('./config/config');
const errorToPojo = require('./utils/errorToPojo');

const URL = `https://phishstats.info:2096/api/phishing`;
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

  if (_configFieldIsValid(proxy)) {
    process.env.HTTP_PROXY = proxy;
    process.env.HTTPS_PROXY = proxy;
  }

  gaxios.instance.defaults = {
    agent: httpsAgent
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
    let detailMsg = 'There was an unexpected error';

    if (err.response) {
      detailMsg = `Received unexpected HTTP status ${err.response.status}`;
    } else if (err.request) {
      detailMsg = `There was an HTTP err`;
    } else {
      detailMsg = err.message;
    }
    return cb(errorToPojo(detailMsg, err));
  }

  Logger.trace({ lookupResults }, 'Lookup results');
  return cb(null, lookupResults);
};

function buildEntityQuery(entity) {
  switch (entity.type) {
    case 'IPv4':
      return `(ip,eq,${entity.value})`;
    case 'IPv6':
      return `(ip,eq,${entity.value})`;
    case 'domain':
      return `(host,eq,${entity.value})~or(domain,eq,${entity.value})`;
    case 'hash':
      return `(hash,eq,${entity.value})`;
  }
}

const lookUpEntity = async (entity) => {
  let results;

  const requestOptions = {
    url: URL,
    params: {
      _where: buildEntityQuery(entity),
      _size: 10,
      _page: 1
    }
  };

  Logger.debug({ requestOptions }, 'request options');

  results = await gaxios.request(requestOptions);

  return {
    entity,
    data:
      Array.isArray(results.data) && results.data.length > 0
        ? { summary: getSummary(results.data), details: results.data }
        : null
  };
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
