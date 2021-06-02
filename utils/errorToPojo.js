const errorToPojo = (detail, err) => {
  return err instanceof Error
    ? {
        ...err,
        name: err.name,
        message: err.message,
        stack: err.stack,
        detail: detail ? detail : 'Unexpected error encountered'
      }
    : err;
};

module.exports = errorToPojo;
