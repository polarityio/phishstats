
const { request } = require('gaxios')

const URL = `https://phishstats.info:2096/api/phishing?_where=`

const startup = logger => {
  Logger = logger; 
}

const doLookup = async (entities, options, cb) => {
  let lookupResults = []

  for(const entity of entities) {
    try {
      if (entity.isIP) {
        await lookupIP(entity, (err, result) => {
          if (!err) {
            lookupResults.push(result)
          } 
        })
      }

      if (entity.isDomain) {
        await lookupDomain(entity, (err, result) => {
          if (!err) {
            lookupResults.push(result)
          }
        })
      }

    }catch(err) {
      return cb(err, null)
   }
  }
cb(null, lookupResults)
}


const lookupIP = async (entity, done) => {
  let results
  try { 
      results = await request({
          url: URL + `${entity.value}`
      })
  } catch (err) {
      if (err || results.status !== 200) {
          done(err || results)
      }
  }
  done(null, {
      entity: entity, 
      data: {
          summary: [entity.value],
          details: results.data
      }
  })
}

const lookupDomain = async (entity, done) => {
  let results 
  try {
      results = await request({
          url: URL + `${entity.value}`
      })
  } catch(err) {
      if (err || results.status !== 200) {
          done(err || results.data)
      }
  }
  done(null, {
      entity: entity, 
      data: {
          summary: [entity.value],
          details: results.data
      }
  })
}

module.exports = {
  doLookup,
  startup,
};

