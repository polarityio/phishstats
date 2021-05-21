polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    entity: Ember.computed.alias('block.entity'),
});
