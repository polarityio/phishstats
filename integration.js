const async = require('async');
const fs = require('fs');
const gaxios = require('gaxios');
const https = require('https');
const config = require('./config/config');
const gaxiosErrorToPojo = require('./utils/errorToPojo');

const MAX_PARALLEL_LOOKUPS = 5;
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
      MAX_PARALLEL_LOOKUPS
    );
  } catch (err) {
    const errPojo = gaxiosErrorToPojo(err);
    Logger.error({ err: errPojo }, 'Lookup Error');
    return cb(errPojo);
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
        ? { summary: getSummary(entity, results.data), details: results.data }
        : null
  };
};

const getSummary = (entity, data) => {
  let tags = [];

  const totalResults = data.length;
  let maxScore = 0;
  let hasVulns = false;
  const domainsOrIps = new Set();

  data.forEach((result) => {
    if (entity.type === 'IPv4' || entity.type === 'IPv6') {
      if (result.domain) {
        domainsOrIps.add(result.domain);
      }
    } else if (entity.type === 'domain') {
      if (result.ip) {
        domainsOrIps.add(result.ip);
      }
    }
    if (result.score > maxScore) {
      maxScore = result.score;
    }
    if (result.vulns) {
      hasVulns = true;
    }
  });

  tags = tags.concat(Array.from(domainsOrIps.values()));

  tags.push(`Max Score: ${maxScore}`);
  if (hasVulns) {
    tags.push(`Has Vulnerabilities`);
  }

  if (tags.length === 0) {
    tags.push(`Results: ${totalResults}`);
  }

  return tags;
};

module.exports = {
  doLookup,
  startup
};
