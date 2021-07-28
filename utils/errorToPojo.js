/**
 * Gaxios errors return an error of type GaxiosError.  This is an error which wraps contains
 * an error code as well as as the underlying error response if available.
 * @param detail
 * @param err
 * @returns {{stack: string, name: string, detail: (*|string), message: string}|*}
 */
const { GaxiosError } = require('gaxios');

function gaxiosErrorToPojo(err) {
  if (err instanceof GaxiosError) {
    let detail = 'There was an unexpected error';
    let data = '';
    if (err.response) {
      detail = `Received unexpected HTTP status ${err.response.status}`;
      data = err.response.data;
    } else if (err.request) {
      detail = `There was an HTTP error`;
    } else {
      detail = err.message;
    }
    return {
      name: err.name,
      message: err.message,
      request: err.request,
      data,
      detail
    };
  } else if (err instanceof Error) {
    // Handle Node Errors as well as FetchError
    // See https://github.com/node-fetch/node-fetch/blob/master/docs/ERROR-HANDLING.md for information
    // on Node Fetch error structure
    return {
      name: err.name,
      message: err.message,
      stack: err.stack,
      code: err.code,
      errno: err.errno,
      type: err.type,
      detail: err.message ? err.message : 'There was an unexpected error'
    };
  } else {
    return err;
  }
}

module.exports = gaxiosErrorToPojo;
